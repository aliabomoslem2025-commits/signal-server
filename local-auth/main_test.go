package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestTicketRoundTripAndTamperDetection(t *testing.T) {
	s := &server{cfg: config{ticketSecret: []byte("0123456789abcdef0123456789abcdef")}}
	original := ticketClaims{
		Phone:         "+4915112345678",
		AndroidIDHash: "aabbccdd",
		JTI:           "ticket-id-1",
		ExpiresAt:     time.Now().Add(time.Minute).Unix(),
	}

	ticket, err := s.signTicket(original)
	if err != nil {
		t.Fatalf("signTicket() error = %v", err)
	}
	got, err := s.verifyTicket(ticket)
	if err != nil {
		t.Fatalf("verifyTicket() error = %v", err)
	}
	if got.Phone != original.Phone || got.AndroidIDHash != original.AndroidIDHash || got.JTI != original.JTI {
		t.Fatalf("verifyTicket() = %#v, want %#v", got, original)
	}

	if _, err := s.verifyTicket(ticket + "tampered"); err == nil {
		t.Fatal("verifyTicket() accepted a modified signature")
	}
}

func TestRegistrationSessionIDUsesBase64URL(t *testing.T) {
	ticket := "lan1." + strings.Repeat("+/payload", 8)
	sessionID := base64.RawURLEncoding.EncodeToString([]byte("LAN1." + ticket))

	if strings.ContainsAny(sessionID, "+/=") {
		t.Fatalf("registration session ID is not URL-safe: %q", sessionID)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(sessionID)
	if err != nil {
		t.Fatalf("could not decode registration session ID: %v", err)
	}
	if string(decoded) != "LAN1."+ticket {
		t.Fatalf("decoded session ID = %q, want %q", decoded, "LAN1."+ticket)
	}
}


func TestParsePublicKeyAcceptsOnlyP256(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256DER, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p256PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p256DER}))
	if _, err := parsePublicKey(p256PEM); err != nil {
		t.Fatalf("parsePublicKey() rejected P-256 key: %v", err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p384PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p384DER}))
	if _, err := parsePublicKey(p384PEM); err == nil {
		t.Fatal("parsePublicKey() accepted non-P-256 key")
	}
}

func TestRandomCodeIsSixDecimalDigits(t *testing.T) {
	for i := 0; i < 100; i++ {
		code, err := randomCode()
		if err != nil {
			t.Fatalf("randomCode() error = %v", err)
		}
		if len(code) != 6 {
			t.Fatalf("randomCode() length = %d, want 6", len(code))
		}
		for _, digit := range code {
			if digit < '0' || digit > '9' {
				t.Fatalf("randomCode() = %q, contains non-decimal digit", code)
			}
		}
	}
}

func TestAndroidIDHashIsKeyedAndDeterministic(t *testing.T) {
	s := &server{cfg: config{androidHashSecret: []byte("0123456789abcdef0123456789abcdef")}}
	first := s.hashAndroidID("  android-id-1234  ")
	second := s.hashAndroidID("android-id-1234")
	other := s.hashAndroidID("android-id-5678")

	if string(first) != string(second) {
		t.Fatal("hashAndroidID() is not stable after whitespace normalization")
	}
	if string(first) == string(other) {
		t.Fatal("different Android IDs produced the same HMAC")
	}
}
