package modules

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/vflame6/bruter/utils"
)

// RDP NLA/CredSSP authentication constants
const (
	// X.224 Connection Request
	tpktVersion = 3

	// RDP Negotiation Request types
	typeRDPNegReq  byte = 0x01
	protoNLA       uint32 = 0x03 // TLS + CredSSP

	// RDP Negotiation Response types
	typeRDPNegRsp  byte = 0x02
	typeRDPNegFail byte = 0x03

	// NTLM message types
	ntlmNegotiate    uint32 = 1
	ntlmChallenge    uint32 = 2
	ntlmAuthenticate uint32 = 3

	// NTLM negotiate flags
	ntlmNegUnicode       uint32 = 0x00000001
	ntlmNegNTLM          uint32 = 0x00000200
	ntlmNegSeal          uint32 = 0x00000020
	ntlmNegSign          uint32 = 0x00000010
	ntlmReqTarget        uint32 = 0x00000004
	ntlmNegAlwaysSign    uint32 = 0x00008000
	ntlmNegExtendedSess  uint32 = 0x00080000
	ntlmNegTargetInfo    uint32 = 0x00800000
	ntlmNeg56            uint32 = 0x80000000
	ntlmNeg128           uint32 = 0x20000000
	ntlmNegKeyExchange   uint32 = 0x40000000
)

var ntlmSignature = []byte("NTLMSSP\x00")

// RDPHandler is an implementation of ModuleHandler for Remote Desktop Protocol (RDP).
// Default port: 3389. Implements NLA (Network Level Authentication) via CredSSP/NTLM.
// The username can be specified as "DOMAIN\username" or just "username".
func RDPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	username := credential.Username
	domain := ""
	if idx := strings.IndexByte(username, '\\'); idx >= 0 {
		domain = username[:idx]
		username = username[idx+1:]
	}

	// Step 1: TCP connect
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// Step 2: Send X.224 Connection Request with NLA negotiation
	if err := sendX224ConnReq(conn); err != nil {
		return false, err
	}

	// Step 3: Read X.224 Connection Confirm
	nlaSupported, err := readX224ConnConfirm(conn)
	if err != nil {
		return false, err
	}
	if !nlaSupported {
		return false, fmt.Errorf("server does not support NLA")
	}

	// Step 4: TLS handshake
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{""},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false, fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()

	// Step 5: CredSSP/NTLM authentication
	return credSSPAuth(tlsConn, domain, username, credential.Password, timeout)
}

// sendX224ConnReq sends an X.224 Connection Request with RDP Negotiation Request for NLA
func sendX224ConnReq(conn net.Conn) error {
	// RDP Negotiation Request: type=0x01, flags=0, length=8, protocol=NLA(3)
	negReq := []byte{typeRDPNegReq, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}

	// X.224 CR: length indicator, CR code (0xe0), dst-ref, src-ref, class
	x224 := []byte{(byte)(6 + len(negReq)), 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00}
	x224 = append(x224, negReq...)

	// TPKT header: version=3, reserved=0, length(2 bytes big-endian)
	totalLen := 4 + len(x224)
	tpkt := []byte{tpktVersion, 0x00, byte(totalLen >> 8), byte(totalLen & 0xff)}
	pkt := append(tpkt, x224...)

	_, err := conn.Write(pkt)
	return err
}

// readX224ConnConfirm reads the X.224 Connection Confirm and checks for NLA support
func readX224ConnConfirm(conn net.Conn) (bool, error) {
	// Read TPKT header (4 bytes)
	tpktHdr := make([]byte, 4)
	if _, err := readFull(conn, tpktHdr); err != nil {
		return false, fmt.Errorf("read tpkt: %w", err)
	}
	if tpktHdr[0] != tpktVersion {
		return false, fmt.Errorf("invalid tpkt version: %d", tpktHdr[0])
	}
	pktLen := int(binary.BigEndian.Uint16(tpktHdr[2:4]))
	if pktLen < 7 || pktLen > 1024 {
		return false, fmt.Errorf("invalid tpkt length: %d", pktLen)
	}

	// Read the rest
	data := make([]byte, pktLen-4)
	if _, err := readFull(conn, data); err != nil {
		return false, fmt.Errorf("read x224: %w", err)
	}

	// X.224 CC: first byte is length indicator, second byte should be 0xd0 (CC)
	if len(data) < 2 || data[1] != 0xd0 {
		return false, fmt.Errorf("not a connection confirm: 0x%02x", data[1])
	}

	// Check for RDP Negotiation Response after the X.224 header (7 bytes from TPKT start = 3 bytes into data)
	// The neg response starts after the X.224 CC header (variable length)
	li := int(data[0])
	if li+1 > len(data) {
		return false, fmt.Errorf("invalid length indicator")
	}

	// Search for negotiation response in the payload
	for i := 1; i < len(data)-3; i++ {
		if data[i] == typeRDPNegRsp && i+7 < len(data) {
			// Selected protocol is at offset +4 (4 bytes LE)
			selectedProto := binary.LittleEndian.Uint32(data[i+4 : i+8])
			return selectedProto&0x03 != 0, nil // NLA or TLS+NLA
		}
		if data[i] == typeRDPNegFail {
			return false, fmt.Errorf("negotiation failure")
		}
	}

	// No negotiation response found — server might only support standard RDP
	return false, nil
}

// credSSPAuth performs CredSSP authentication using NTLM
func credSSPAuth(conn net.Conn, domain, username, password string, timeout time.Duration) (bool, error) {
	// Send TSRequest with NTLM Negotiate
	negMsg := buildNTLMNegotiate()
	tsReq := buildTSRequest(1, negMsg, nil)
	if err := writeCredSSP(conn, tsReq); err != nil {
		return false, err
	}

	// Read TSRequest with NTLM Challenge
	tsRespData, err := readCredSSP(conn)
	if err != nil {
		return false, err
	}

	challengeMsg, err := extractNTLMFromTSRequest(tsRespData)
	if err != nil {
		return false, err
	}

	if len(challengeMsg) < 32 {
		return false, fmt.Errorf("invalid ntlm challenge")
	}

	// Parse challenge and build authenticate message
	authMsg, err := buildNTLMAuthenticate(challengeMsg, domain, username, password)
	if err != nil {
		return false, err
	}

	// Send TSRequest with NTLM Authenticate
	tsReq2 := buildTSRequest(3, authMsg, nil)
	if err := writeCredSSP(conn, tsReq2); err != nil {
		return false, err
	}

	// Read response — success or failure
	respData, err := readCredSSP(conn)
	if err != nil {
		// Connection closed or error usually means auth failure
		return false, nil
	}

	// If we get an error code in TSRequest, auth failed
	if hasCredSSPError(respData) {
		return false, nil
	}

	// If we get a valid response without error, auth succeeded
	return true, nil
}

// buildNTLMNegotiate builds an NTLM Type 1 (Negotiate) message
func buildNTLMNegotiate() []byte {
	flags := ntlmNegUnicode | ntlmNegNTLM | ntlmReqTarget | ntlmNegAlwaysSign |
		ntlmNegExtendedSess | ntlmNegTargetInfo | ntlmNeg56 | ntlmNeg128 | ntlmNegKeyExchange

	buf := new(bytes.Buffer)
	buf.Write(ntlmSignature)
	_ = binary.Write(buf, binary.LittleEndian, ntlmNegotiate)
	_ = binary.Write(buf, binary.LittleEndian, flags)
	// Domain name fields (empty): len, maxlen, offset
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	// Workstation fields (empty): len, maxlen, offset
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	return buf.Bytes()
}

// buildNTLMAuthenticate builds an NTLM Type 3 (Authenticate) message
func buildNTLMAuthenticate(challenge []byte, domain, username, password string) ([]byte, error) {
	// Parse server challenge (8 bytes at offset 24)
	if len(challenge) < 32 {
		return nil, fmt.Errorf("challenge too short")
	}
	serverChallenge := challenge[24:32]

	// Get target info if available
	var targetInfo []byte
	if len(challenge) > 44 {
		tiLen := binary.LittleEndian.Uint16(challenge[40:42])
		tiOff := binary.LittleEndian.Uint32(challenge[44:48])
		if int(tiOff)+int(tiLen) <= len(challenge) {
			targetInfo = challenge[tiOff : tiOff+uint32(tiLen)]
		}
	}

	// Compute NTLMv2 response
	ntHash := ntlmHash(password)
	usernameUpper := strings.ToUpper(username)
	identity := toUTF16LE(usernameUpper)
	identity = append(identity, toUTF16LE(domain)...)

	responseKeyNT := hmacMD5(ntHash, identity)

	// Client challenge (8 random bytes)
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, err
	}

	// Build NTLMv2 client blob
	blob := new(bytes.Buffer)
	blob.WriteByte(0x01) // RespType
	blob.WriteByte(0x01) // HiRespType
	blob.Write([]byte{0, 0, 0, 0, 0, 0}) // Reserved
	// Timestamp (current time as Windows FILETIME)
	now := time.Now().UnixNano()/100 + 116444736000000000
	_ = binary.Write(blob, binary.LittleEndian, now)
	blob.Write(clientChallenge)
	blob.Write([]byte{0, 0, 0, 0}) // Reserved
	if targetInfo != nil {
		blob.Write(targetInfo)
	}
	blob.Write([]byte{0, 0, 0, 0}) // End of target info

	blobBytes := blob.Bytes()
	temp := append(serverChallenge, blobBytes...)
	ntProofStr := hmacMD5(responseKeyNT, temp)
	ntResponse := append(ntProofStr, blobBytes...)

	// Build Type 3 message
	domainBytes := toUTF16LE(domain)
	userBytes := toUTF16LE(username)
	workstation := toUTF16LE("")

	// Calculate offsets (header is 88 bytes for NTLMv2)
	offset := uint32(88)
	domainOff := offset
	offset += uint32(len(domainBytes))
	userOff := offset
	offset += uint32(len(userBytes))
	wsOff := offset
	offset += uint32(len(workstation))
	lmOff := offset
	lmResponse := make([]byte, 24) // Empty LM response for NTLMv2
	offset += uint32(len(lmResponse))
	ntOff := offset

	flags := ntlmNegUnicode | ntlmNegNTLM | ntlmNegAlwaysSign |
		ntlmNegExtendedSess | ntlmNegTargetInfo | ntlmNeg56 | ntlmNeg128 | ntlmNegKeyExchange

	msg := new(bytes.Buffer)
	msg.Write(ntlmSignature)
	_ = binary.Write(msg, binary.LittleEndian, ntlmAuthenticate)
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(lmResponse)))
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(lmResponse)))
	_ = binary.Write(msg, binary.LittleEndian, lmOff)
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(ntResponse)))
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(ntResponse)))
	_ = binary.Write(msg, binary.LittleEndian, ntOff)
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(domainBytes)))
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(domainBytes)))
	_ = binary.Write(msg, binary.LittleEndian, domainOff)
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(userBytes)))
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(userBytes)))
	_ = binary.Write(msg, binary.LittleEndian, userOff)
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(workstation)))
	_ = binary.Write(msg, binary.LittleEndian, uint16(len(workstation)))
	_ = binary.Write(msg, binary.LittleEndian, wsOff)
	// Encrypted random session key (empty)
	_ = binary.Write(msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(msg, binary.LittleEndian, uint32(0))
	_ = binary.Write(msg, binary.LittleEndian, flags)

	msg.Write(domainBytes)
	msg.Write(userBytes)
	msg.Write(workstation)
	msg.Write(lmResponse)
	msg.Write(ntResponse)

	return msg.Bytes(), nil
}

// ntlmHash computes the NT hash (MD4 of UTF-16LE password)
func ntlmHash(password string) []byte {
	utf16pw := toUTF16LE(password)
	return md4Hash(utf16pw)
}

// md4Hash computes MD4 (used by NTLM). Implemented inline to avoid dependencies.
func md4Hash(data []byte) []byte {
	// Simple MD4 implementation
	var h [4]uint32
	h[0] = 0x67452301
	h[1] = 0xefcdab89
	h[2] = 0x98badcfe
	h[3] = 0x10325476

	// Padding
	origLen := len(data)
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0)
	}
	bits := uint64(origLen) * 8
	data = binary.LittleEndian.AppendUint64(data, bits)

	// Process blocks
	for i := 0; i < len(data); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(data[i+j*4 : i+j*4+4])
		}

		a, b, c, d := h[0], h[1], h[2], h[3]

		// Round 1
		ff := func(a, b, c, d, x uint32, s uint) uint32 {
			return rotl32(a+((b&c)|((^b)&d))+x, s)
		}
		a = ff(a, b, c, d, x[0], 3)
		d = ff(d, a, b, c, x[1], 7)
		c = ff(c, d, a, b, x[2], 11)
		b = ff(b, c, d, a, x[3], 19)
		a = ff(a, b, c, d, x[4], 3)
		d = ff(d, a, b, c, x[5], 7)
		c = ff(c, d, a, b, x[6], 11)
		b = ff(b, c, d, a, x[7], 19)
		a = ff(a, b, c, d, x[8], 3)
		d = ff(d, a, b, c, x[9], 7)
		c = ff(c, d, a, b, x[10], 11)
		b = ff(b, c, d, a, x[11], 19)
		a = ff(a, b, c, d, x[12], 3)
		d = ff(d, a, b, c, x[13], 7)
		c = ff(c, d, a, b, x[14], 11)
		b = ff(b, c, d, a, x[15], 19)

		// Round 2
		gg := func(a, b, c, d, x uint32, s uint) uint32 {
			return rotl32(a+((b&c)|(b&d)|(c&d))+x+0x5a827999, s)
		}
		a = gg(a, b, c, d, x[0], 3)
		d = gg(d, a, b, c, x[4], 5)
		c = gg(c, d, a, b, x[8], 9)
		b = gg(b, c, d, a, x[12], 13)
		a = gg(a, b, c, d, x[1], 3)
		d = gg(d, a, b, c, x[5], 5)
		c = gg(c, d, a, b, x[9], 9)
		b = gg(b, c, d, a, x[13], 13)
		a = gg(a, b, c, d, x[2], 3)
		d = gg(d, a, b, c, x[6], 5)
		c = gg(c, d, a, b, x[10], 9)
		b = gg(b, c, d, a, x[14], 13)
		a = gg(a, b, c, d, x[3], 3)
		d = gg(d, a, b, c, x[7], 5)
		c = gg(c, d, a, b, x[11], 9)
		b = gg(b, c, d, a, x[15], 13)

		// Round 3
		hh := func(a, b, c, d, x uint32, s uint) uint32 {
			return rotl32(a+(b^c^d)+x+0x6ed9eba1, s)
		}
		a = hh(a, b, c, d, x[0], 3)
		d = hh(d, a, b, c, x[8], 9)
		c = hh(c, d, a, b, x[4], 11)
		b = hh(b, c, d, a, x[12], 15)
		a = hh(a, b, c, d, x[2], 3)
		d = hh(d, a, b, c, x[10], 9)
		c = hh(c, d, a, b, x[6], 11)
		b = hh(b, c, d, a, x[14], 15)
		a = hh(a, b, c, d, x[1], 3)
		d = hh(d, a, b, c, x[9], 9)
		c = hh(c, d, a, b, x[5], 11)
		b = hh(b, c, d, a, x[13], 15)
		a = hh(a, b, c, d, x[3], 3)
		d = hh(d, a, b, c, x[11], 9)
		c = hh(c, d, a, b, x[7], 11)
		b = hh(b, c, d, a, x[15], 15)

		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
	}

	result := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(result[i*4:], h[i])
	}
	return result
}

func rotl32(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func toUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// desEncrypt encrypts 8 bytes with a 7-byte DES key (used in LM/NTLM)
func desEncrypt(key7 []byte, data []byte) []byte {
	key8 := des7to8(key7)
	c, _ := des.NewCipher(key8)
	out := make([]byte, 8)
	c.Encrypt(out, data)
	return out
}

func des7to8(key7 []byte) []byte {
	if len(key7) < 7 {
		padded := make([]byte, 7)
		copy(padded, key7)
		key7 = padded
	}
	return []byte{
		key7[0],
		(key7[0] << 7) | (key7[1] >> 1),
		(key7[1] << 6) | (key7[2] >> 2),
		(key7[2] << 5) | (key7[3] >> 3),
		(key7[3] << 4) | (key7[4] >> 4),
		(key7[4] << 3) | (key7[5] >> 5),
		(key7[5] << 2) | (key7[6] >> 6),
		key7[6] << 1,
	}
}

// CredSSP/TSRequest helpers using minimal ASN.1 DER encoding

// buildTSRequest builds a CredSSP TSRequest message
func buildTSRequest(version int, negoToken []byte, authInfo []byte) []byte {
	// TSRequest ::= SEQUENCE {
	//   version    [0] INTEGER,
	//   negoTokens [1] OPTIONAL,
	//   authInfo   [2] OPTIONAL,
	// }
	inner := new(bytes.Buffer)

	// version [0] INTEGER
	verBytes := asn1Int(version)
	inner.Write(asn1Explicit(0, verBytes))

	// negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
	if negoToken != nil {
		tokenOctet := asn1OctetString(negoToken)
		tokenExplicit := asn1Explicit(0, tokenOctet)
		tokenSeq := asn1Sequence(tokenExplicit)
		tokensSeq := asn1Sequence(tokenSeq)
		inner.Write(asn1Explicit(1, tokensSeq))
	}

	// authInfo [2] OCTET STRING
	if authInfo != nil {
		inner.Write(asn1Explicit(2, asn1OctetString(authInfo)))
	}

	return asn1Sequence(inner.Bytes())
}

func asn1Sequence(data []byte) []byte {
	return asn1TLV(0x30, data)
}

func asn1OctetString(data []byte) []byte {
	return asn1TLV(0x04, data)
}

func asn1Int(v int) []byte {
	if v < 128 {
		return asn1TLV(0x02, []byte{byte(v)})
	}
	// Multi-byte integer
	b := new(bytes.Buffer)
	_ = binary.Write(b, binary.BigEndian, int32(v))
	data := b.Bytes()
	// Strip leading zeros
	for len(data) > 1 && data[0] == 0 {
		data = data[1:]
	}
	return asn1TLV(0x02, data)
}

func asn1Explicit(tag int, data []byte) []byte {
	return asn1TLV(byte(0xa0+tag), data)
}

func asn1TLV(tag byte, data []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(tag)
	l := len(data)
	if l < 128 {
		buf.WriteByte(byte(l))
	} else if l < 256 {
		buf.WriteByte(0x81)
		buf.WriteByte(byte(l))
	} else {
		buf.WriteByte(0x82)
		buf.WriteByte(byte(l >> 8))
		buf.WriteByte(byte(l & 0xff))
	}
	buf.Write(data)
	return buf.Bytes()
}

// writeCredSSP writes a CredSSP message (framed as-is over TLS)
func writeCredSSP(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

// readCredSSP reads a CredSSP TSRequest from the connection
func readCredSSP(conn net.Conn) ([]byte, error) {
	// Read ASN.1 tag + length
	hdr := make([]byte, 2)
	if _, err := readFull(conn, hdr); err != nil {
		return nil, err
	}

	var totalLen int
	consumed := 2
	if hdr[1] < 128 {
		totalLen = int(hdr[1])
	} else {
		lenBytes := int(hdr[1] & 0x7f)
		if lenBytes > 4 {
			return nil, fmt.Errorf("asn1 length too large")
		}
		lb := make([]byte, lenBytes)
		if _, err := readFull(conn, lb); err != nil {
			return nil, err
		}
		consumed += lenBytes
		for _, b := range lb {
			totalLen = (totalLen << 8) | int(b)
		}
	}

	if totalLen > 65536 {
		return nil, fmt.Errorf("credSSP message too large: %d", totalLen)
	}

	data := make([]byte, consumed+totalLen)
	copy(data, hdr)
	if consumed > 2 {
		copy(data[2:consumed], data[2:consumed])
	}
	if _, err := readFull(conn, data[consumed:]); err != nil {
		return nil, err
	}
	return data, nil
}

// extractNTLMFromTSRequest extracts the NTLM token from a CredSSP TSRequest
func extractNTLMFromTSRequest(data []byte) ([]byte, error) {
	// Look for NTLMSSP signature in the data
	idx := bytes.Index(data, ntlmSignature)
	if idx < 0 {
		return nil, fmt.Errorf("no NTLM message in TSRequest")
	}
	return data[idx:], nil
}

// hasCredSSPError checks if a TSRequest contains an error code
func hasCredSSPError(data []byte) bool {
	// errorCode is [3] in TSRequest — look for context tag 0xa3
	return bytes.Contains(data, []byte{0xa3})
}

// readFull is defined in socks5.go
