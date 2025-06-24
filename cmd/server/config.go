package main

import (
	"errors"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const configFilePath = "config.yaml"

// TLSConfig 定义了所有与TLS相关的配置
type TLSConfig struct {
	Mode     string `yaml:"mode"`       // "acme", "file", "self-signed"
	Domain   string `yaml:"domain"`     // for acme mode
	Email    string `yaml:"email"`      // for acme mode
	CacheDir string `yaml:"cache_dir"`  // for acme mode
	CertFile string `yaml:"cert_file"`  // for file mode
	KeyFile  string `yaml:"key_file"`   // for file mode
}

// FallbackConfig 定义了回落目标的配置
type FallbackConfig struct {
	Address            string `yaml:"address"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Config 定义了应用程序的所有配置项
type Config struct {
	Listen        string         `yaml:"listen"`
	Password      string         `yaml:"password"`
	PaddingScheme string         `yaml:"padding_scheme"`
	LogLevel      string         `yaml:"log_level"`
	TLS           TLSConfig      `yaml:"tls"`
	Fallback      FallbackConfig `yaml:"fallback"`
}

// createDefaultConfig 创建一个带有详细注释的默认配置文件
func createDefaultConfig() error {
	defaultConfig := `# AnyTLS-Go Server Configuration File
# This file is in YAML format.

# Server listen address and port.
# Example: "0.0.0.0:8443"
listen: "0.0.0.0:8443"

# Connection password. This must be set.
password: "your-strong-password-here"

# Log level.
# Available options: "trace", "debug", "info", "warn", "error", "fatal", "panic".
log_level: "info"

# Path to the custom padding scheme file.
# Leave empty to use the default padding scheme.
# Example: "/path/to/your/padding.txt"
padding_scheme: ""

# TLS certificate configuration.
tls:
  # Certificate mode. Three modes are supported:
  # 1. "acme": Automatically obtain and renew certificates from Let's Encrypt.
  # 2. "file": Use a certificate from local files.
  # 3. "self-signed": Generate a self-signed certificate on startup (default).
  mode: "self-signed"

  # --- ACME Mode Settings ---
  # Required when mode is "acme".
  domain: "your.domain.com"
  email: "your-email@example.com"
  cache_dir: "./cert_cache"

  # --- File Mode Settings ---
  # Required when mode is "file".
  cert_file: "/path/to/your/fullchain.pem"
  key_file: "/path/to/your/privkey.pem"

# Fallback configuration for failed authentications.
fallback:
  # Address to forward traffic to.
  # Supports plain TCP and TLS (auto-detects port 443 for TLS).
  # Example: "127.0.0.1:80" or "localhost:443"
  # Leave empty to disable fallback.
  address: ""

  # For TLS fallbacks (e.g., to port 443), whether to skip verification
  # of the backend server's certificate.
  # Set to true if your fallback service uses a self-signed certificate.
  insecure_skip_verify: true
`
	return os.WriteFile(configFilePath, []byte(defaultConfig), 0644)
}

// LoadConfig 加载配置，如果配置文件不存在则创建默认配置
func LoadConfig() (*Config, error) {
	// 检查配置文件是否存在
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		logrus.Infof("Configuration file not found. Creating a default '%s'. Please edit it and restart the server.", configFilePath)
		if err := createDefaultConfig(); err != nil {
			return nil, err
		}
		// 提示用户编辑后退出
		return nil, os.ErrNotExist
	}

	// 读取并解析配置文件
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	// 验证配置
	switch cfg.TLS.Mode {
	case "acme":
		if cfg.TLS.Domain == "" || cfg.TLS.Email == "" {
			return nil, errors.New("for 'acme' mode, 'domain' and 'email' must be set in the TLS config")
		}
	case "file":
		if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
			return nil, errors.New("for 'file' mode, 'cert_file' and 'key_file' must be set in the TLS config")
		}
	case "self-signed", "":
		// 默认为 self-signed
		cfg.TLS.Mode = "self-signed"
	default:
		return nil, errors.New("invalid TLS mode: " + cfg.TLS.Mode + ". Must be 'acme', 'file', or 'self-signed'")
	}

	if cfg.TLS.CacheDir == "" {
		cfg.TLS.CacheDir = "./cert_cache"
	}

	return &cfg, nil
}