package main

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"database/sql"
)

//go:embed schema.sql
var schema string

type config struct {
	listenAddr       string
	databaseURL      string
	adminToken       []byte
	internalToken    []byte
	ticketSecret     []byte
	androidHashSecret []byte
	allowedOrigins   map[string]bool
	challengeTTL     time.Duration
}

type server struct {
	db  *sql.DB
	cfg config
}

type apiError struct {
	Error string `json:"error"`
}

type userRequest struct {
	Phone       string `json:"phone"`
	DisplayName string `json:"displayName"`
}

type deviceRequest struct {
	AndroidID   string `json:"androidId"`
	PublicKeyPEM string `json:"publicKeyPem"`
	Label       string `json:"label"`
}

type challengeRequest struct {
	Phone     string `json:"phone"`
	AndroidID string `json:"androidId"`
}

type challengeResponse struct {
	ChallengeID string    `json:"challengeId"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type verifyRequest struct {
	ChallengeID string `json:"challengeId"`
	Signature   string `json:"signature"`
}

type verifyResponse struct {
	VerificationCode string    `json:"verificationCode"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type completeRequest struct {
	ChallengeID string `json:"challengeId"`
	Code        string `json:"code"`
}

type ticketClaims struct {
	Phone         string `json:"phone"`
	AndroidIDHash string `json:"androidIdHash"`
	JTI           string `json:"jti"`
	ExpiresAt     int64  `json:"exp"`
}

type consumeTicketResponse struct {
	Phone         string `json:"phone"`
	AndroidIDHash string `json:"androidIdHash"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}

	db, err := sql.Open("pgx", cfg.databaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "database initialization failed:", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, "database connection failed:", err)
		os.Exit(1)
	}
	if _, err := db.Exec(schema); err != nil {
		fmt.Fprintln(os.Stderr, "database migration failed:", err)
		os.Exit(1)
	}

	s := &server{db: db, cfg: cfg}
	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Println("local-auth listening on", cfg.listenAddr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "HTTP server failed:", err)
		os.Exit(1)
	}
}

func loadConfig() (config, error) {
	getRequired := func(name string) (string, error) {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}

	var cfg config
	var err error
	if cfg.listenAddr, err = getRequired("LISTEN_ADDR"); err != nil {
		return cfg, err
	}
	if cfg.databaseURL, err = getRequired("DATABASE_URL"); err != nil {
		return cfg, err
	}
	if cfg.adminToken, err = secret("ADMIN_TOKEN"); err != nil {
		return cfg, err
	}
	if cfg.internalToken, err = secret("INTERNAL_TOKEN"); err != nil {
		return cfg, err
	}
	if cfg.ticketSecret, err = secret("TICKET_HMAC_SECRET"); err != nil {
		return cfg, err
	}
	if cfg.androidHashSecret, err = secret("ANDROID_ID_HASH_SECRET"); err != nil {
		return cfg, err
	}
	cfg.challengeTTL = 3 * time.Minute
	if raw := os.Getenv("CHALLENGE_TTL_SECONDS"); raw != "" {
		var seconds int
		if _, err := fmt.Sscanf(raw, "%d", &seconds); err != nil || seconds < 30 || seconds > 600 {
			return cfg, errors.New("CHALLENGE_TTL_SECONDS must be between 30 and 600")
		}
		cfg.challengeTTL = time.Duration(seconds) * time.Second
	}
	cfg.allowedOrigins = make(map[string]bool)
	for _, origin := range strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			cfg.allowedOrigins[origin] = true
		}
	}
	return cfg, nil
}

func secret(name string) ([]byte, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if len(value) < 32 {
		return nil, fmt.Errorf("%s must contain at least 32 characters", name)
	}
	return []byte(value), nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := s.db.PingContext(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/v1/local-auth/challenge", s.handleChallenge)
	mux.HandleFunc("/v1/local-auth/verify", s.handleVerify)
	mux.HandleFunc("/v1/local-auth/complete", s.handleComplete)
	mux.HandleFunc("/v1/local-auth/internal/validate-ticket", s.requireBearer(s.cfg.internalToken, s.handleValidateTicket))
	mux.HandleFunc("/v1/local-auth/internal/consume-ticket", s.requireBearer(s.cfg.internalToken, s.handleConsumeTicket))
	mux.HandleFunc("/v1/local-auth/admin/users", s.requireBearer(s.cfg.adminToken, s.handleUsers))
	mux.HandleFunc("/v1/local-auth/admin/user-status/", s.requireBearer(s.cfg.adminToken, s.handleAdminUserStatus))
	mux.HandleFunc("/v1/local-auth/admin/events", s.requireBearer(s.cfg.adminToken, s.handleAdminEvents))
	mux.HandleFunc("/v1/local-auth/admin/users/", s.requireBearer(s.cfg.adminToken, s.handleUserSubresource))
	mux.HandleFunc("/v1/local-auth/admin/devices/", s.requireBearer(s.cfg.adminToken, s.handleDevice))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			if !s.cfg.allowedOrigins[origin] {
				writeError(w, http.StatusForbidden, "origin not allowed")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (s *server) requireBearer(expected []byte, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		provided := []byte(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
		if !hmac.Equal(provided, expected) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain one JSON object")
		return false
	}
	return true
}

func (s *server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.QueryContext(r.Context(), `
			SELECT u.phone, u.display_name, u.active, u.created_at,
			       COUNT(d.id) FILTER (WHERE d.active = TRUE)
			FROM local_auth_users u
			LEFT JOIN local_auth_devices d ON d.phone = u.phone
			GROUP BY u.phone ORDER BY u.phone`)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list users")
			return
		}
		defer rows.Close()
		users := make([]map[string]any, 0)
		for rows.Next() {
			var phone, displayName string
			var active bool
			var createdAt time.Time
			var deviceCount int
			if err := rows.Scan(&phone, &displayName, &active, &createdAt, &deviceCount); err != nil {
				writeError(w, http.StatusInternalServerError, "could not read users")
				return
			}
			users = append(users, map[string]any{
				"phone": phone, "displayName": displayName, "active": active,
				"createdAt": createdAt, "activeDevices": deviceCount,
			})
		}
		if err := rows.Err(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read users")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	case http.MethodPost:
		var request userRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		request.Phone = strings.TrimSpace(request.Phone)
		request.DisplayName = strings.TrimSpace(request.DisplayName)
		if !phonePattern.MatchString(request.Phone) || len(request.DisplayName) > 120 {
			writeError(w, http.StatusBadRequest, "phone must be E.164 and displayName must be at most 120 characters")
			return
		}
		_, err := s.db.ExecContext(r.Context(), `
			INSERT INTO local_auth_users(phone, display_name, active)
			VALUES($1, $2, TRUE)
			ON CONFLICT(phone) DO UPDATE SET display_name = EXCLUDED.display_name,
				active = TRUE, updated_at = NOW()`, request.Phone, request.DisplayName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not save user")
			return
		}
		s.recordAdminEvent(r, "user.created_or_enabled", request.Phone, map[string]any{"displayName": request.DisplayName})
		writeJSON(w, http.StatusCreated, map[string]string{"phone": request.Phone})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) handleUserSubresource(w http.ResponseWriter, r *http.Request) {
	relative := strings.TrimPrefix(r.URL.Path, "/v1/local-auth/admin/users/")
	parts := strings.Split(strings.Trim(relative, "/"), "/")
	if len(parts) == 1 && r.Method == http.MethodDelete {
		phone, err := urlPathUnescape(parts[0])
		if err != nil || !phonePattern.MatchString(phone) {
			writeError(w, http.StatusBadRequest, "invalid phone")
			return
		}
		result, err := s.db.ExecContext(r.Context(), "DELETE FROM local_auth_users WHERE phone = $1", phone)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete user")
			return
		}
		count, _ := result.RowsAffected()
		if count == 0 {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		s.recordAdminEvent(r, "user.deleted", phone, nil)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(parts) == 2 && parts[1] == "devices" {
		phone, err := urlPathUnescape(parts[0])
		if err != nil || !phonePattern.MatchString(phone) {
			writeError(w, http.StatusBadRequest, "invalid phone")
			return
		}
		if r.Method == http.MethodGet {
			rows, err := s.db.QueryContext(r.Context(), `
				SELECT id, label, active, created_at, last_seen_at
				FROM local_auth_devices WHERE phone = $1 ORDER BY created_at DESC`, phone)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not list devices")
				return
			}
			defer rows.Close()
			devices := make([]map[string]any, 0)
			for rows.Next() {
				var id, label string
				var active bool
				var createdAt time.Time
				var lastSeen sql.NullTime
				if err := rows.Scan(&id, &label, &active, &createdAt, &lastSeen); err != nil {
					writeError(w, http.StatusInternalServerError, "could not read devices")
					return
				}
				var lastSeenValue any
				if lastSeen.Valid {
					lastSeenValue = lastSeen.Time
				}
				devices = append(devices, map[string]any{
					"id": id, "label": label, "active": active,
					"createdAt": createdAt, "lastSeenAt": lastSeenValue,
				})
			}
			if err := rows.Err(); err != nil {
				writeError(w, http.StatusInternalServerError, "could not read devices")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
			return
		}
		if r.Method == http.MethodPost {
			var request deviceRequest
			if !decodeJSON(w, r, &request) {
				return
			}
			request.AndroidID = strings.TrimSpace(request.AndroidID)
			request.Label = strings.TrimSpace(request.Label)
			if len(request.AndroidID) < 4 || len(request.AndroidID) > 256 || len(request.Label) > 120 {
				writeError(w, http.StatusBadRequest, "invalid Android ID or label")
				return
			}
			if _, err := parsePublicKey(request.PublicKeyPEM); err != nil {
				writeError(w, http.StatusBadRequest, "publicKeyPem must be a valid ECDSA P-256 SubjectPublicKeyInfo PEM")
				return
			}
			var active bool
			if err := s.db.QueryRowContext(r.Context(), "SELECT active FROM local_auth_users WHERE phone = $1", phone).Scan(&active); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					writeError(w, http.StatusNotFound, "user must be created before enrolling a device")
				} else {
					writeError(w, http.StatusInternalServerError, "could not check user")
				}
				return
			}
			if !active {
				writeError(w, http.StatusForbidden, "user is disabled")
				return
			}
			deviceID, err := randomHex(16)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not create device")
				return
			}
			idHash := s.hashAndroidID(request.AndroidID)
			err = s.db.QueryRowContext(r.Context(), `
				INSERT INTO local_auth_devices(id, phone, android_id_hash, public_key_pem, label, active)
				VALUES($1, $2, $3, $4, $5, TRUE)
				ON CONFLICT(phone, android_id_hash) DO UPDATE SET
					public_key_pem = EXCLUDED.public_key_pem, label = EXCLUDED.label,
					active = TRUE
				RETURNING id`, deviceID, phone, idHash, strings.TrimSpace(request.PublicKeyPEM), request.Label).Scan(&deviceID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not enroll device")
				return
			}
			s.recordAdminEvent(r, "device.enrolled", phone, map[string]any{"deviceId": deviceID, "label": request.Label})
			writeJSON(w, http.StatusCreated, map[string]string{"deviceId": deviceID})
			return
		}
	}
	writeError(w, http.StatusNotFound, "route not found")
}

func (s *server) handleDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, err := urlPathUnescape(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/local-auth/admin/devices/"), "/"))
	if err != nil || id == "" {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	result, err := s.db.ExecContext(r.Context(), "UPDATE local_auth_devices SET active = FALSE WHERE id = $1 AND active = TRUE", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke device")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "active device not found")
		return
	}
	s.recordAdminEvent(r, "device.revoked", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request challengeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Phone = strings.TrimSpace(request.Phone)
	request.AndroidID = strings.TrimSpace(request.AndroidID)
	if !phonePattern.MatchString(request.Phone) || len(request.AndroidID) < 4 || len(request.AndroidID) > 256 {
		writeError(w, http.StatusBadRequest, "invalid phone or Android ID")
		return
	}
	idHash := s.hashAndroidID(request.AndroidID)
	var enabled bool
	err := s.db.QueryRowContext(r.Context(), `
		SELECT (u.active AND d.active)
		FROM local_auth_users u JOIN local_auth_devices d ON d.phone = u.phone
		WHERE u.phone = $1 AND d.android_id_hash = $2`, request.Phone, idHash).Scan(&enabled)
	if err != nil || !enabled {
		// Deliberately do not reveal whether the phone or device is registered.
		writeError(w, http.StatusUnauthorized, "device is not authorized")
		return
	}
	var recent int
	if err := s.db.QueryRowContext(r.Context(), `
		SELECT COUNT(*) FROM local_auth_challenges
		WHERE (phone = $1 OR android_id_hash = $2)
		  AND created_at > NOW() - INTERVAL '10 minutes'`, request.Phone, idHash).Scan(&recent); err != nil {
		writeError(w, http.StatusInternalServerError, "could not check authentication rate limit")
		return
	}
	if recent >= 10 {
		writeError(w, http.StatusTooManyRequests, "too many authentication attempts")
		return
	}
	id, err := randomHex(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create challenge")
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create challenge")
		return
	}
	expires := time.Now().UTC().Add(s.cfg.challengeTTL)
	_, err = s.db.ExecContext(r.Context(), `
		INSERT INTO local_auth_challenges(id, phone, android_id_hash, nonce, expires_at)
		VALUES($1, $2, $3, $4, $5)`, id, request.Phone, idHash, nonce, expires)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save challenge")
		return
	}
	writeJSON(w, http.StatusOK, challengeResponse{
		ChallengeID: id,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		ExpiresAt: expires,
	})
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request verifyRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature must be standard base64 ASN.1 ECDSA")
		return
	}
	var phone string
	var idHash, nonce []byte
	var expires time.Time
	var verified sql.NullTime
	var attempts int
	var publicKeyPEM string
	err = s.db.QueryRowContext(r.Context(), `
		SELECT c.phone, c.android_id_hash, c.nonce, c.expires_at, c.verified_at, c.attempts, d.public_key_pem
		FROM local_auth_challenges c
		JOIN local_auth_users u ON u.phone = c.phone AND u.active = TRUE
		JOIN local_auth_devices d ON d.phone = c.phone AND d.android_id_hash = c.android_id_hash AND d.active = TRUE
		WHERE c.id = $1`, request.ChallengeID).Scan(&phone, &idHash, &nonce, &expires, &verified, &attempts, &publicKeyPEM)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "challenge is invalid or expired")
		return
	}
	if time.Now().UTC().After(expires) || verified.Valid || attempts >= 5 {
		writeError(w, http.StatusUnauthorized, "challenge is invalid, expired, or already used")
		return
	}
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "enrolled public key is invalid")
		return
	}
	nonceEncoded := base64.RawURLEncoding.EncodeToString(nonce)
	message := []byte("signal-local-auth-v1\n" + request.ChallengeID + "\n" + phone + "\n" + nonceEncoded)
	// The Android client signs this canonical message using the device's non-exportable Keystore private key.
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		_, _ = s.db.ExecContext(r.Context(), "UPDATE local_auth_challenges SET attempts = attempts + 1 WHERE id = $1", request.ChallengeID)
		writeError(w, http.StatusUnauthorized, "device proof is invalid")
		return
	}
	code, err := randomCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create verification code")
		return
	}
	codeHash := s.hashCode(request.ChallengeID, code)
	result, err := s.db.ExecContext(r.Context(), `
		UPDATE local_auth_challenges SET verified_at = NOW(), code_hash = $2
		WHERE id = $1 AND verified_at IS NULL AND expires_at > NOW() AND attempts < 5`,
		request.ChallengeID, codeHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not verify device")
		return
	}
	updated, _ := result.RowsAffected()
	if updated != 1 {
		writeError(w, http.StatusUnauthorized, "challenge has already been used")
		return
	}
	_, _ = s.db.ExecContext(r.Context(), "UPDATE local_auth_devices SET last_seen_at = NOW() WHERE phone = $1 AND android_id_hash = $2", phone, idHash)
	writeJSON(w, http.StatusOK, verifyResponse{VerificationCode: code, ExpiresAt: expires})
}

func (s *server) handleComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request completeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not begin verification")
		return
	}
	defer tx.Rollback()

	var phone string
	var idHash, storedCodeHash []byte
	var expires time.Time
	var verified sql.NullTime
	var completed sql.NullTime
	var codeAttempts int
	err = tx.QueryRowContext(r.Context(), `
		SELECT phone, android_id_hash, code_hash, expires_at, verified_at, completed_at, code_attempts
		FROM local_auth_challenges WHERE id = $1 FOR UPDATE`, request.ChallengeID).
		Scan(&phone, &idHash, &storedCodeHash, &expires, &verified, &completed, &codeAttempts)
	if err != nil || !verified.Valid || completed.Valid || codeAttempts >= 5 || time.Now().UTC().After(expires) {
		writeError(w, http.StatusUnauthorized, "verification code is invalid or expired")
		return
	}
	providedHash := s.hashCode(request.ChallengeID, request.Code)
	if !hmac.Equal(storedCodeHash, providedHash) {
		if _, updateErr := tx.ExecContext(r.Context(), "UPDATE local_auth_challenges SET code_attempts = code_attempts + 1 WHERE id = $1", request.ChallengeID); updateErr != nil {
			writeError(w, http.StatusInternalServerError, "could not record verification attempt")
			return
		}
		if commitErr := tx.Commit(); commitErr != nil {
			writeError(w, http.StatusInternalServerError, "could not record verification attempt")
			return
		}
		writeError(w, http.StatusUnauthorized, "verification code is invalid or expired")
		return
	}
	jti, err := randomHex(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create registration ticket")
		return
	}
	ticketExpiry := time.Now().UTC().Add(2 * time.Minute)
	claims := ticketClaims{
		Phone: phone, AndroidIDHash: hex.EncodeToString(idHash),
		JTI: jti, ExpiresAt: ticketExpiry.Unix(),
	}
	ticket, err := s.signTicket(claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not sign registration ticket")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
		INSERT INTO local_auth_tickets(jti, phone, android_id_hash, expires_at)
		VALUES($1, $2, $3, $4)`, jti, phone, idHash, ticketExpiry); err != nil {
		writeError(w, http.StatusInternalServerError, "could not persist registration ticket")
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE local_auth_challenges SET completed_at = NOW() WHERE id = $1", request.ChallengeID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not complete verification")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not complete verification")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"registrationTicket": ticket,
		"expiresAt": ticketExpiry,
		// Signal Server decodes registration session IDs with Base64.getUrlDecoder().
		"sessionId": base64.RawURLEncoding.EncodeToString([]byte("LAN1." + ticket)),
	})
}

func (s *server) handleValidateTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request struct { Ticket string `json:"ticket"` }
	if !decodeJSON(w, r, &request) {
		return
	}
	claims, err := s.verifyTicket(request.Ticket)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "registration ticket is invalid or expired")
		return
	}
	var phone string
	var idHash []byte
	var expires time.Time
	var consumed sql.NullTime
	err = s.db.QueryRowContext(r.Context(), `
		SELECT t.phone, t.android_id_hash, t.expires_at, t.consumed_at
		FROM local_auth_tickets t
		JOIN local_auth_users u ON u.phone = t.phone AND u.active = TRUE
		JOIN local_auth_devices d ON d.phone = t.phone
		  AND d.android_id_hash = t.android_id_hash AND d.active = TRUE
		WHERE t.jti = $1`, claims.JTI).
		Scan(&phone, &idHash, &expires, &consumed)
	if err != nil || consumed.Valid || time.Now().UTC().After(expires) ||
		phone != claims.Phone || hex.EncodeToString(idHash) != claims.AndroidIDHash {
		writeError(w, http.StatusUnauthorized, "registration ticket has already been used or expired")
		return
	}
	writeJSON(w, http.StatusOK, consumeTicketResponse{
		Phone: phone, AndroidIDHash: hex.EncodeToString(idHash), ExpiresAt: expires,
	})
}

func (s *server) handleConsumeTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request struct { Ticket string `json:"ticket"` }
	if !decodeJSON(w, r, &request) {
		return
	}
	claims, err := s.verifyTicket(request.Ticket)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "registration ticket is invalid or expired")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not redeem ticket")
		return
	}
	defer tx.Rollback()
	var phone string
	var idHash []byte
	var expires time.Time
	var consumed sql.NullTime
	err = tx.QueryRowContext(r.Context(), `
		SELECT t.phone, t.android_id_hash, t.expires_at, t.consumed_at
		FROM local_auth_tickets t
		JOIN local_auth_users u ON u.phone = t.phone AND u.active = TRUE
		JOIN local_auth_devices d ON d.phone = t.phone
		  AND d.android_id_hash = t.android_id_hash AND d.active = TRUE
		WHERE t.jti = $1
		FOR UPDATE OF t`, claims.JTI).
		Scan(&phone, &idHash, &expires, &consumed)
	if err != nil || consumed.Valid || time.Now().UTC().After(expires) ||
		phone != claims.Phone || hex.EncodeToString(idHash) != claims.AndroidIDHash {
		writeError(w, http.StatusUnauthorized, "registration ticket has already been used or expired")
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE local_auth_tickets SET consumed_at = NOW() WHERE jti = $1", claims.JTI); err != nil {
		writeError(w, http.StatusInternalServerError, "could not redeem ticket")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not redeem ticket")
		return
	}
	writeJSON(w, http.StatusOK, consumeTicketResponse{
		Phone: phone, AndroidIDHash: hex.EncodeToString(idHash), ExpiresAt: expires,
	})
}

func (s *server) hashAndroidID(value string) []byte {
	mac := hmac.New(sha256.New, s.cfg.androidHashSecret)
	mac.Write([]byte(strings.TrimSpace(value)))
	return mac.Sum(nil)
}

func (s *server) hashCode(challengeID, code string) []byte {
	mac := hmac.New(sha256.New, s.cfg.ticketSecret)
	mac.Write([]byte(challengeID + ":" + code))
	return mac.Sum(nil)
}

func (s *server) signTicket(claims ticketClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.cfg.ticketSecret)
	mac.Write([]byte("lan1." + encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "lan1." + encoded + "." + signature, nil
}

func (s *server) verifyTicket(ticket string) (ticketClaims, error) {
	var claims ticketClaims
	parts := strings.Split(ticket, ".")
	if len(parts) != 3 || parts[0] != "lan1" {
		return claims, errors.New("invalid ticket format")
	}
	mac := hmac.New(sha256.New, s.cfg.ticketSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return claims, errors.New("invalid ticket signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return claims, errors.New("invalid ticket payload")
	}
	if claims.Phone == "" || claims.JTI == "" || claims.ExpiresAt <= time.Now().UTC().Unix() {
		return claims, errors.New("expired ticket")
	}
	return claims, nil
}

func parsePublicKey(value string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("expected SubjectPublicKeyInfo PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("only ECDSA P-256 keys are supported")
	}
	return key, nil
}

func randomHex(bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func urlPathUnescape(value string) (string, error) {
	return url.PathUnescape(value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, apiError{Error: message})
}
