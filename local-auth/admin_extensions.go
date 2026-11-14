package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type adminUserStatusRequest struct {
	Active *bool `json:"active"`
}

// handleAdminUserStatus enables or disables a pre-provisioned account without deleting its device enrollments.
// Disabling a user immediately prevents new device challenges and invalidates unconsumed registration tickets.
func (s *server) handleAdminUserStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	phone, err := url.PathUnescape(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/local-auth/admin/user-status/"), "/"))
	if err != nil || !phonePattern.MatchString(phone) {
		writeError(w, http.StatusBadRequest, "invalid phone")
		return
	}

	var request adminUserStatusRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Active == nil {
		writeError(w, http.StatusBadRequest, "active must be provided")
		return
	}

	result, err := s.db.ExecContext(r.Context(),
		"UPDATE local_auth_users SET active = $1, updated_at = NOW() WHERE phone = $2",
		*request.Active, phone)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update user status")
		return
	}
	changed, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update user status")
		return
	}
	if changed == 0 {
		var exists bool
		if err := s.db.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM local_auth_users WHERE phone = $1)", phone).Scan(&exists); err != nil {
			writeError(w, http.StatusInternalServerError, "could not verify user")
			return
		}
		if !exists {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
	}

	event := "user.disabled"
	if *request.Active {
		event = "user.enabled"
	}
	s.recordAdminEvent(r, event, phone, map[string]any{"active": *request.Active})
	writeJSON(w, http.StatusOK, map[string]any{"phone": phone, "active": *request.Active})
}

// handleAdminEvents returns a bounded, newest-first administrative audit trail.
func (s *server) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		limit = value
	}

	rows, err := s.db.QueryContext(r.Context(), `
		SELECT id, event_type, target, metadata, source_ip, created_at
		FROM local_auth_admin_events
		ORDER BY created_at DESC, id DESC
		LIMIT $1`, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list administrative events")
		return
	}
	defer rows.Close()

	events := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var eventType, target, sourceIP string
		var metadata []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &eventType, &target, &metadata, &sourceIP, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read administrative events")
			return
		}
		if len(metadata) == 0 {
			metadata = []byte("{}")
		}
		events = append(events, map[string]any{
			"id": id,
			"eventType": eventType,
			"target": target,
			"metadata": json.RawMessage(metadata),
			"sourceIp": sourceIP,
			"createdAt": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read administrative events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// recordAdminEvent captures administrative mutations. Event storage failures are logged but do not
// roll back the primary action; deployments should monitor the local-auth service logs for DB failures.
func (s *server) recordAdminEvent(r *http.Request, eventType, target string, metadata map[string]any) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		encoded = []byte("{}")
	}
	sourceIP := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(sourceIP); splitErr == nil {
		sourceIP = host
	}
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
		// Trust this header only when the sidecar is behind a reverse proxy controlled by the LAN operator.
		if net.ParseIP(forwarded) != nil {
			sourceIP = forwarded
		}
	}
	if _, err := s.db.ExecContext(context.Background(), `
		INSERT INTO local_auth_admin_events(event_type, target, metadata, source_ip)
		VALUES($1, $2, $3::jsonb, $4)`, eventType, target, encoded, sourceIP); err != nil {
		_ = sql.ErrNoRows // keep imports/diagnostics explicit for SQL-backed audit writes
		println("local-auth: failed to persist admin event:", err.Error())
	}
}
