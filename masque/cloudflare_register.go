package masque

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CloudflareRegistration handles Cloudflare WARP registration and enrollment
type CloudflareRegistration struct {
	APIUrl     string
	APIVersion string
	Headers    map[string]string
}

// NewCloudflareRegistration creates a new registration handler
func NewCloudflareRegistration() *CloudflareRegistration {
	return &CloudflareRegistration{
		APIUrl:     "https://api.cloudflareclient.com",
		APIVersion: "v0a4471",
		Headers: map[string]string{
			"User-Agent":        "WARP for Android",
			"CF-Client-Version": "a-6.35-4471",
			"Content-Type":      "application/json; charset=UTF-8",
			"Connection":        "Keep-Alive",
		},
	}
}

// AccountData represents the response from Cloudflare registration
type AccountData struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

// DeviceUpdate represents the device enrollment payload
type DeviceUpdate struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

// RegisterAndEnroll performs complete Cloudflare WARP registration and MASQUE enrollment
func (cr *CloudflareRegistration) RegisterAndEnroll(ctx context.Context, model, locale, deviceName string) (*MasqueConfig, error) {
	// Step 1: Register account with Cloudflare
	accountData, err := cr.registerAccount(ctx, model, locale, "")
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// Step 2: Generate ECDSA key pair for MASQUE
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Step 3: Enroll MASQUE key
	updatedAccount, err := cr.enrollMasqueKey(ctx, accountData, privKey, deviceName)
	if err != nil {
		return nil, fmt.Errorf("MASQUE enrollment failed: %w", err)
	}

	// Step 4: Create MASQUE config
	config := &MasqueConfig{
		PrivateKey:     cr.encodePrivateKey(privKey),
		EndpointV4:     cr.parseEndpoint(updatedAccount.Config.Peers[0].Endpoint.V4),
		EndpointV6:     cr.parseEndpoint(updatedAccount.Config.Peers[0].Endpoint.V6),
		EndpointPubKey: updatedAccount.Config.Peers[0].PublicKey,
		License:        updatedAccount.Account.License,
		ID:             updatedAccount.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccount.Config.Interface.Addresses.V4,
		IPv6:           updatedAccount.Config.Interface.Addresses.V6,
	}

	return config, nil
}

// registerAccount registers a new Cloudflare WARP account
func (cr *CloudflareRegistration) registerAccount(ctx context.Context, model, locale, jwt string) (*AccountData, error) {
	// Generate dummy WireGuard key for initial registration (Android app behavior)
	wgKey, err := cr.generateRandomWgKey()
	if err != nil {
		return nil, fmt.Errorf("WG key generation failed: %w", err)
	}

	serial, err := cr.generateRandomSerial()
	if err != nil {
		return nil, fmt.Errorf("serial generation failed: %w", err)
	}

	payload := map[string]interface{}{
		"key":                 wgKey,
		"install_id":          serial,
		"fcm_token":           serial,
		"tos":                 time.Now().Format(time.RFC3339Nano),
		"model":               model,
		"serial_number":       serial,
		"locale":              locale,
		"type":                "Android",
		"warp_enabled":        false,
		"referrer":            "",
		"role":                "",
		"fallback_domains":    "",
		"usage_stats_enabled": true,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("JSON marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cr.APIUrl+"/"+cr.APIVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	for k, v := range cr.Headers {
		req.Header.Set(k, v)
	}

	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed: %s - %s", resp.Status, string(body))
	}

	var accountData AccountData
	if err := json.NewDecoder(resp.Body).Decode(&accountData); err != nil {
		return nil, fmt.Errorf("response decode failed: %w", err)
	}

	return &accountData, nil
}

// enrollMasqueKey enrolls the ECDSA key for MASQUE tunneling
func (cr *CloudflareRegistration) enrollMasqueKey(ctx context.Context, accountData *AccountData, privKey *ecdsa.PrivateKey, deviceName string) (*AccountData, error) {
	// Encode public key for enrollment in PKIX format (like usque does)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	deviceUpdate := DeviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubKeyBytes),
		KeyType: "secp256r1", // MASQUE uses ECDSA P-256
		TunType: "masque",    // Switch to MASQUE mode
	}

	if deviceName != "" {
		deviceUpdate.Name = deviceName
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return nil, fmt.Errorf("JSON marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", cr.APIUrl+"/"+cr.APIVersion+"/reg/"+accountData.ID, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	for k, v := range cr.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("response read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment failed: %s - %s", resp.Status, string(body))
	}

	var updatedAccount AccountData
	if err := json.Unmarshal(body, &updatedAccount); err != nil {
		return nil, fmt.Errorf("response decode failed: %w", err)
	}

	return &updatedAccount, nil
}

// Helper functions
func (cr *CloudflareRegistration) generateRandomWgKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func (cr *CloudflareRegistration) generateRandomSerial() (string, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", serial), nil
}

func (cr *CloudflareRegistration) encodePrivateKey(privKey *ecdsa.PrivateKey) string {
	// Use standard ASN.1 DER encoding (compatible with usque/masque-plus)
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		// Fallback to raw bytes if marshaling fails (should not happen)
		keyBytes = privKey.D.Bytes()
		// Pad to 32 bytes for P-256
		if len(keyBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(keyBytes):], keyBytes)
			keyBytes = padded
		}
	}
	return base64.StdEncoding.EncodeToString(keyBytes)
}

func (cr *CloudflareRegistration) parseEndpoint(endpoint string) string {
	// Remove port suffix (e.g., ":0" or "]:0")
	if len(endpoint) > 2 {
		if endpoint[len(endpoint)-2:] == ":0" {
			return endpoint[:len(endpoint)-2]
		}
		if endpoint[len(endpoint)-3:] == "]:0" && endpoint[0] == '[' {
			return endpoint[1 : len(endpoint)-3]
		}
	}
	return endpoint
}

// AutoRegisterOrLoad automatically registers a new device or loads existing config
func AutoRegisterOrLoad(ctx context.Context, configPath, deviceName string) (*MasqueConfig, error) {
	// Try to load existing config first
	if config, err := LoadMasqueConfig(configPath); err == nil {
		return config, nil
	}

	// Register new device
	cr := NewCloudflareRegistration()
	config, err := cr.RegisterAndEnroll(ctx, "PC", "en_US", deviceName)
	if err != nil {
		return nil, fmt.Errorf("auto-registration failed: %w", err)
	}

	// Save config
	if err := config.SaveToFile(configPath); err != nil {
		return nil, fmt.Errorf("config save failed: %w", err)
	}

	return config, nil
}
