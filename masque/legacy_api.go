package masque

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
)

// MasqueClient is a compatibility alias for older callers.
type MasqueClient = MasqueAdapter

// MasqueConfig is a compatibility alias for older config helpers.
type MasqueConfig = config.Config

// AutoRegisterOptions keeps backward compatibility with older helpers.
type AutoRegisterOptions struct {
	ConfigPath string
	DeviceName string
	Model      string
	Locale     string
	ForceRenew bool
	Endpoint   string
	UseIPv6    bool
	Logger     *slog.Logger
	License    string
}

func AutoLoadOrRegister(ctx context.Context, configPath, deviceName string, logger *slog.Logger) (*MasqueClient, error) {
	return AutoLoadOrRegisterWithOptions(ctx, AutoRegisterOptions{
		ConfigPath: configPath,
		DeviceName: deviceName,
		Logger:     logger,
	})
}

func AutoLoadOrRegisterWithOptions(ctx context.Context, opts AutoRegisterOptions) (*MasqueClient, error) {
	if opts.ForceRenew && opts.ConfigPath != "" {
		_ = os.Remove(opts.ConfigPath)
	}
	return NewMasqueAdapter(ctx, AdapterConfig{
		ConfigPath: opts.ConfigPath,
		DeviceName: opts.DeviceName,
		Endpoint:   opts.Endpoint,
		UseIPv6:    opts.UseIPv6,
		Logger:     opts.Logger,
		License:    opts.License,
	})
}

func AutoRegisterOrLoad(ctx context.Context, configPath, deviceName string) (*MasqueConfig, error) {
	if _, err := os.Stat(configPath); err == nil {
		return LoadMasqueConfig(configPath)
	}

	cfg, err := RegisterAndEnroll("PC", "en_US", "", deviceName, true)
	if err != nil {
		return nil, err
	}
	if err := SaveConfig(cfg, configPath); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadMasqueConfig(path string) (*MasqueConfig, error) {
	if err := config.LoadConfig(path); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	cfg := config.AppConfig
	return &cfg, nil
}

func SaveConfig(cfg *MasqueConfig, path string) error {
	return saveConfigFile(path, cfg)
}

func ValidateConfig(path string) error {
	cfg, err := LoadMasqueConfig(path)
	if err != nil {
		return err
	}
	if cfg.PrivateKey == "" || cfg.EndpointV4 == "" || cfg.ID == "" {
		return fmt.Errorf("invalid MASQUE config: missing required fields")
	}
	return nil
}

func DeleteConfig(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func RegisterAndEnroll(model, locale, teamToken, deviceName string, acceptTOS bool) (*MasqueConfig, error) {
	if model == "" {
		model = "PC"
	}
	if locale == "" {
		locale = "en_US"
	}

	accountData, err := api.Register(model, locale, teamToken, acceptTOS)
	if err != nil {
		return nil, fmt.Errorf("failed to register device: %w", err)
	}

	privKey, pubKey, err := generateEcKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, deviceName)
	if err != nil {
		if apiErr != nil {
			return nil, fmt.Errorf("failed to enroll key: %w (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return nil, fmt.Errorf("failed to enroll key: %w", err)
	}

	if len(updatedAccountData.Config.Peers) == 0 || updatedAccountData.Config.Peers[0].Endpoint.V4 == "" || updatedAccountData.Config.Peers[0].PublicKey == "" || updatedAccountData.ID == "" {
		return nil, fmt.Errorf("registration failed: incomplete data returned")
	}

	cfg := &MasqueConfig{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     stripPortSuffix(updatedAccountData.Config.Peers[0].Endpoint.V4),
		EndpointV6:     stripPortSuffix(updatedAccountData.Config.Peers[0].Endpoint.V6),
		EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
		License:        updatedAccountData.Account.License,
		ID:             updatedAccountData.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
		IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
	}
	return cfg, nil
}
