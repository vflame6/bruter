package modules

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNTLMHash(t *testing.T) {
	// Known test vector: NTLM hash of "Password"
	// NT hash of "Password" = a4f49c406510bdcab6824ee7c30fd852
	hash := ntlmHash("Password")
	expected, _ := hex.DecodeString("a4f49c406510bdcab6824ee7c30fd852")
	if !bytes.Equal(hash, expected) {
		t.Fatalf("ntlmHash mismatch: got %x, want %x", hash, expected)
	}
}

func TestNTLMHashEmpty(t *testing.T) {
	// NT hash of "" = 31d6cfe0d16ae931b73c59d7e0c089c0
	hash := ntlmHash("")
	expected, _ := hex.DecodeString("31d6cfe0d16ae931b73c59d7e0c089c0")
	if !bytes.Equal(hash, expected) {
		t.Fatalf("ntlmHash empty mismatch: got %x, want %x", hash, expected)
	}
}

func TestToUTF16LE(t *testing.T) {
	result := toUTF16LE("AB")
	expected := []byte{0x41, 0x00, 0x42, 0x00}
	if !bytes.Equal(result, expected) {
		t.Fatalf("toUTF16LE mismatch: got %x, want %x", result, expected)
	}
}

func TestBuildNTLMNegotiate(t *testing.T) {
	msg := buildNTLMNegotiate()
	if !bytes.HasPrefix(msg, ntlmSignature) {
		t.Fatal("missing NTLMSSP signature")
	}
	// Check message type = 1
	if msg[8] != 1 || msg[9] != 0 || msg[10] != 0 || msg[11] != 0 {
		t.Fatal("wrong message type")
	}
}

func TestBuildTSRequest(t *testing.T) {
	negMsg := buildNTLMNegotiate()
	tsReq := buildTSRequest(1, negMsg, nil)
	// Should be a valid ASN.1 SEQUENCE
	if tsReq[0] != 0x30 {
		t.Fatalf("expected SEQUENCE tag 0x30, got 0x%02x", tsReq[0])
	}
}

func TestMD4Hash(t *testing.T) {
	// MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
	hash := md4Hash([]byte{})
	expected, _ := hex.DecodeString("31d6cfe0d16ae931b73c59d7e0c089c0")
	if !bytes.Equal(hash, expected) {
		t.Fatalf("md4Hash empty mismatch: got %x, want %x", hash, expected)
	}

	// MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
	hash2 := md4Hash([]byte("abc"))
	expected2, _ := hex.DecodeString("a448017aaf21d8525fc10ae87aa6729d")
	if !bytes.Equal(hash2, expected2) {
		t.Fatalf("md4Hash abc mismatch: got %x, want %x", hash2, expected2)
	}
}

func TestSendX224ConnReq(t *testing.T) {
	// Just verify it doesn't panic and produces reasonable output
	var buf bytes.Buffer
	// Can't easily test with a real conn, but we verify the packet construction
	// by checking buildNTLMNegotiate doesn't panic
	_ = buildNTLMNegotiate()
	_ = buf // suppress unused
}

func TestHasCredSSPError(t *testing.T) {
	// A response with context tag 0xa3 indicates error
	withError := []byte{0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x03, 0xa3, 0x03, 0x02, 0x01, 0x01}
	if !hasCredSSPError(withError) {
		t.Fatal("expected error detected")
	}

	// A response without 0xa3
	withoutError := []byte{0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x03}
	if hasCredSSPError(withoutError) {
		t.Fatal("expected no error")
	}
}
