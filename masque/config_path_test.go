package masque

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGetDefaultConfigPath tests platform-specific config path generation
func TestGetDefaultConfigPath(t *testing.T) {
	path := GetDefaultConfigPath()

	if path == "" {
		t.Fatal("GetDefaultConfigPath returned empty string")
	}

	if !filepath.IsAbs(path) && runtime.GOOS != "android" && runtime.GOOS != "ios" {
		// On desktop platforms, path should be absolute
		t.Errorf("Expected absolute path, got: %s", path)
	}

	if filepath.Ext(path) != ".json" {
		t.Errorf("Expected .json extension, got: %s", path)
	}

	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		t.Errorf("Config path should have a parent directory, got: %s", path)
	}

	t.Logf("Platform: %s, Config path: %s", runtime.GOOS, path)
}

// TestGetConfigDirectory tests platform-specific config directory
func TestGetConfigDirectory(t *testing.T) {
	dir := GetConfigDirectory()

	if dir == "" {
		t.Fatal("GetConfigDirectory returned empty string")
	}

	// Check platform-specific expectations
	switch runtime.GOOS {
	case "windows":
		if !containsAny(dir, []string{"AppData", "Roaming"}) && !containsAny(dir, []string{"vwarp"}) {
			t.Errorf("Windows config dir should contain AppData/Roaming/vwarp, got: %s", dir)
		}
	case "darwin":
		if !containsAny(dir, []string{"Library", "Application Support"}) && !containsAny(dir, []string{"vwarp"}) {
			t.Errorf("macOS config dir should contain Library/Application Support/vwarp, got: %s", dir)
		}
	case "linux":
		if !containsAny(dir, []string{".config"}) && !containsAny(dir, []string{"vwarp"}) {
			t.Errorf("Linux config dir should contain .config/vwarp, got: %s", dir)
		}
	}

	t.Logf("Platform: %s, Config dir: %s", runtime.GOOS, dir)
}

// TestGetMobileConfigPath tests mobile-specific config paths
func TestGetMobileConfigPath(t *testing.T) {
	tests := []struct {
		name       string
		appDataDir string
		wantSuffix string
	}{
		{
			name:       "Android path",
			appDataDir: "/data/data/com.example.app/files",
			wantSuffix: "masque_config.json",
		},
		{
			name:       "iOS path",
			appDataDir: "/var/mobile/Containers/Data/Application/UUID/Library/Application Support",
			wantSuffix: "masque_config.json",
		},
		{
			name:       "Empty fallback",
			appDataDir: "",
			wantSuffix: "masque_config.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := GetMobileConfigPath(tt.appDataDir)

			if !filepath.IsAbs(path) && tt.appDataDir != "" {
				t.Errorf("Expected absolute path when appDataDir is provided, got: %s", path)
			}

			if filepath.Base(path) != tt.wantSuffix {
				t.Errorf("Expected filename %s, got: %s", tt.wantSuffix, filepath.Base(path))
			}

			if tt.appDataDir != "" && !containsSubstring(path, tt.appDataDir) {
				t.Errorf("Expected path to contain %s, got: %s", tt.appDataDir, path)
			}

			t.Logf("Input: %s, Output: %s", tt.appDataDir, path)
		})
	}
}

// TestGetConfigPathWithFallback tests fallback behavior
func TestGetConfigPathWithFallback(t *testing.T) {
	// This test just ensures it doesn't panic and returns something
	path := GetConfigPathWithFallback()

	if path == "" {
		t.Fatal("GetConfigPathWithFallback returned empty string")
	}

	if filepath.Ext(path) != ".json" {
		t.Errorf("Expected .json extension, got: %s", path)
	}

	t.Logf("Fallback path: %s", path)
}

// TestConfigDirectoryCreation tests that directory can be created
func TestConfigDirectoryCreation(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldAppData := os.Getenv("APPDATA")
	oldXDGConfig := os.Getenv("XDG_CONFIG_HOME")

	// Set temp home for testing
	switch runtime.GOOS {
	case "windows":
		os.Setenv("APPDATA", tmpDir)
	case "darwin":
		os.Setenv("HOME", tmpDir)
	case "linux":
		os.Setenv("XDG_CONFIG_HOME", tmpDir)
	default:
		os.Setenv("HOME", tmpDir)
	}

	// Restore original env vars
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("APPDATA", oldAppData)
		os.Setenv("XDG_CONFIG_HOME", oldXDGConfig)
	}()

	// Get config directory
	configDir := GetConfigDirectory()

	// Try to create it
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	// Verify it exists
	stat, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf("Config directory doesn't exist after creation: %v", err)
	}

	if !stat.IsDir() {
		t.Error("Config path is not a directory")
	}

	t.Logf("Successfully created config directory: %s", configDir)
}

// TestConfigPathPlatformSpecifics tests platform-specific behavior
func TestConfigPathPlatformSpecifics(t *testing.T) {
	path := GetDefaultConfigPath()
	dir := GetConfigDirectory()

	// Platform-specific checks
	switch runtime.GOOS {
	case "windows":
		// Windows should use backslashes (filepath handles this automatically)
		if filepath.VolumeName(path) == "" && os.Getenv("APPDATA") != "" {
			t.Error("Windows path should have volume name")
		}

	case "darwin":
		// macOS should be in Library/Application Support
		if !containsAny(path, []string{"Library", "Application Support"}) {
			t.Errorf("macOS path should be in Application Support, got: %s", path)
		}

	case "linux":
		// Linux should use .config
		if !containsAny(path, []string{".config"}) && os.Getenv("HOME") != "" {
			t.Errorf("Linux path should use .config, got: %s", path)
		}
	}

	t.Logf("Platform: %s", runtime.GOOS)
	t.Logf("Config path: %s", path)
	t.Logf("Config dir: %s", dir)
}

// Helper functions

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if containsSubstring(s, substr) {
			return true
		}
	}
	return false
}

func containsSubstring(s, substr string) bool {
	return filepath.Base(s) == substr ||
		filepath.Dir(s) == substr ||
		containsInPath(s, substr)
}

func containsInPath(path, substr string) bool {
	for {
		if filepath.Base(path) == substr {
			return true
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return false
}
