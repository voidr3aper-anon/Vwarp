package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bepass-org/vwarp/masque/usque/internal"
	"github.com/bepass-org/vwarp/masque/usque/models"
)

// Register creates a new user account by registering a WireGuard public key
func Register(model, locale, jwt string, acceptTos bool) (*models.AccountData, error) {
	wgKey, err := internal.GenerateRandomWgPubkey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate wg key: %w", err)
	}
	serial, err := internal.GenerateRandomAndroidSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	if !acceptTos {
		return nil, fmt.Errorf("TOS must be accepted")
	}

	data := models.Registration{
		Key:       wgKey,
		InstallID: "",
		FcmToken:  "",
		Tos:       internal.TimeAsCfString(time.Now()),
		Model:     model,
		Serial:    serial,
		OsVersion: "",
		KeyType:   internal.KeyTypeWg,
		TunType:   internal.TunTypeWg,
		Locale:    locale,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %w", err)
	}

	req, err := http.NewRequest("POST", internal.ApiUrl+"/"+internal.ApiVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}

	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to register: %v", resp.Status)
	}

	var accountData models.AccountData
	if err := json.NewDecoder(resp.Body).Decode(&accountData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &accountData, nil
}

// EnrollKey updates an existing user account with a new MASQUE public key
func EnrollKey(accountData *models.AccountData, pubKey []byte, deviceName string) (*models.AccountData, *models.APIError, error) {
	deviceUpdate := models.DeviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
	}

	if deviceName != "" {
		deviceUpdate.Name = deviceName
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal json: %w", err)
	}

	req, err := http.NewRequest("PATCH", internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+accountData.ID, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, nil, fmt.Errorf("failed to parse error response: %w", err)
		}
		return nil, &apiErr, fmt.Errorf("failed to update: %s", resp.Status)
	}

	var updatedAccountData models.AccountData
	if err := json.Unmarshal(body, &updatedAccountData); err != nil {
		return nil, nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &updatedAccountData, nil, nil
}
