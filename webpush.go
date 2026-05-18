package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const MaxRecordSize uint32 = 4096

var ErrMaxPadExceeded = errors.New("payload has exceeded the maximum length")

// saltFunc generates a salt of 16 bytes
var saltFunc = func() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return salt, err
	}

	return salt, nil
}

// HTTPClient is an interface for sending the notification HTTP request / testing
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Options are config and extra params needed to send a notification
type Options struct {
	AuthScheme      AuthScheme // VAPID authentication scheme, defaults to "vapid"
	HTTPClient      HTTPClient // Will replace with *http.Client by default if not included
	RecordSize      uint32     // Limit the record size
	Subscriber      string     // Sub in VAPID JWT token
	Topic           string     // Set the Topic header to collapse a pending messages (Optional)
	TTL             int        // Set the TTL on the endpoint POST request
	Urgency         Urgency    // Set the Urgency header to change a message priority (Optional)
	VAPIDPublicKey  string     // VAPID public key, passed in VAPID Authorization header
	VAPIDPrivateKey string     // VAPID private key, used to sign VAPID JWT token
	VapidExpiration time.Time  // optional expiration for VAPID JWT token (defaults to now + 12 hours)
}

// Keys are the base64 encoded values from PushSubscription.getKey()
type Keys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

// SendNotification calls SendNotificationWithContext with default context for backwards-compatibility
func SendNotification(message []byte, s *Subscription, options *Options) (*http.Response, error) {
	return SendNotificationWithContext(context.Background(), message, s, options)
}

// SendNotificationWithContext sends a push notification to a subscription's endpoint
// Message Encryption for Web Push, and VAPID protocols.
// FOR MORE INFORMATION SEE RFC8291: https://datatracker.ietf.org/doc/rfc8291
func SendNotificationWithContext(ctx context.Context, message []byte, s *Subscription, options *Options) (*http.Response, error) {
	// Authentication secret (auth_secret)
	authSecret, err := decodeSubscriptionKey(s.Keys.Auth)
	if err != nil {
		return nil, err
	}

	// dh (Diffie Hellman)
	dh, err := decodeSubscriptionKey(s.Keys.P256dh)
	if err != nil {
		return nil, err
	}

	// Generate 16 byte salt
	salt, err := saltFunc()
	if err != nil {
		return nil, err
	}

	// Create the ecdh_secret shared key pair
	curve := ecdh.P256()

	// Application server key pairs (single use)
	localPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	localPublicKey := localPrivateKey.PublicKey().Bytes()

	// Combine application keys with receiver's EC public key
	remotePublicKey, err := curve.NewPublicKey(dh)
	if err != nil {
		return nil, errors.New("unmarshal error: public key is not a valid point on the curve")
	}

	// Derive ECDH shared secret
	sharedECDHSecret, err := localPrivateKey.ECDH(remotePublicKey)
	if err != nil {
		return nil, errors.New("encryption error: ECDH shared secret isn't on curve")
	}

	hash := sha256.New

	// ikm
	prkInfo := make([]byte, 0, len("WebPush: info\x00")+len(dh)+len(localPublicKey))
	prkInfo = append(prkInfo, "WebPush: info\x00"...)
	prkInfo = append(prkInfo, dh...)
	prkInfo = append(prkInfo, localPublicKey...)

	ikm, err := hkdf.Key(hash, sharedECDHSecret, authSecret, string(prkInfo), 32)
	if err != nil {
		return nil, err
	}

	// Derive Content Encryption Key
	contentEncryptionKey, err := hkdf.Key(hash, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}

	// Derive the Nonce
	nonce, err := hkdf.Key(hash, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Get the record size
	recordSize := options.RecordSize
	if recordSize == 0 {
		recordSize = MaxRecordSize
	}

	recordLength := int(recordSize) - 16

	// Encryption Content-Coding Header
	record := make([]byte, 0, int(recordSize))
	record = append(record, salt...)

	var rs [4]byte
	binary.BigEndian.PutUint32(rs[:], recordSize)

	record = append(record, rs[:]...)
	record = append(record, byte(len(localPublicKey)))
	record = append(record, localPublicKey...)

	// Avoid data races by copying the message data
	maxPayloadLen := recordLength - len(record)
	payloadLen := len(message) + 1
	if payloadLen > maxPayloadLen {
		return nil, ErrMaxPadExceeded
	}

	data := make([]byte, maxPayloadLen)
	copy(data, message)

	// Pad content to max record size - 16 - header
	// Padding ending delimiter
	data[len(message)] = 0x02

	// Compose the ciphertext
	record = gcm.Seal(record, nonce, data, nil)

	// POST request
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.Endpoint, bytes.NewReader(record))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Сheck the optional headers
	if len(options.Topic) > 0 {
		req.Header.Set("Topic", options.Topic)
	}

	if isValidUrgency(options.Urgency) {
		req.Header.Set("Urgency", string(options.Urgency))
	}

	expiration := options.VapidExpiration
	if expiration.IsZero() {
		expiration = time.Now().Add(time.Hour * 12)
	}

	// Get VAPID headers
	vapidHeaders, err := generateVAPIDHeaders(
		s.Endpoint,
		options.Subscriber,
		options.VAPIDPublicKey,
		options.VAPIDPrivateKey,
		expiration,
		options.AuthScheme,
	)
	if err != nil {
		return nil, err
	}

	for key, value := range vapidHeaders {
		req.Header.Set(key, value)
	}

	// Send the request
	var client HTTPClient
	if options.HTTPClient != nil {
		client = options.HTTPClient
	} else {
		client = &http.Client{}
	}

	return client.Do(req)
}

// decodeSubscriptionKey decodes a base64 subscription key.
// if necessary, add "=" padding to the key for URL decode
func decodeSubscriptionKey(key string) ([]byte, error) {
	// "=" padding
	switch rem := len(key) % 4; rem {
	case 1:
		key += "==="
	case 2:
		key += "=="
	case 3:
		key += "="
	}

	bytes, err := base64.StdEncoding.DecodeString(key)
	if err == nil {
		return bytes, nil
	}

	return base64.URLEncoding.DecodeString(key)
}
