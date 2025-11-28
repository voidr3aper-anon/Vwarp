package models

import "strings"

// Registration represents the payload for device registration
type Registration struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FcmToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Serial    string `json:"serial_number"`
	OsVersion string `json:"os_version"`
	KeyType   string `json:"key_type"`
	TunType   string `json:"tunnel_type"`
	Locale    string `json:"locale"`
}

// DeviceUpdate represents the payload for updating a device's key
type DeviceUpdate struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

// AccountData represents the response from registration/enrollment
type AccountData struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		ID          string `json:"id"`
		License     string `json:"license"`
		AccountType string `json:"account_type"`
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

// APIError represents an error response from the API
type APIError struct {
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// ErrorsAsString converts API errors to a single string
func (e *APIError) ErrorsAsString(separator string) string {
	var messages []string
	for _, err := range e.Errors {
		messages = append(messages, err.Message)
	}
	return strings.Join(messages, separator)
}
