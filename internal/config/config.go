package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr    string        `yaml:"listen_addr"`
	Upstream      string        `yaml:"upstream"`
	AuditLogPath  string        `yaml:"audit_log_path"`
	MaxBodyBytes  int64         `yaml:"max_body_bytes"`
	Approval      Approval      `yaml:"approval"`
	Rules         []Rule        `yaml:"rules"`
	TimeFormat    string        `yaml:"time_format"`
	DecisionOrder []string      `yaml:"decision_order"`
	Headers       HeaderOptions `yaml:"headers"`
}

type Approval struct {
	Enabled bool          `yaml:"enabled"`
	Token   string        `yaml:"token"`
	TTL     time.Duration `yaml:"ttl"`
}

type HeaderOptions struct {
	AddRequestIDHeader bool `yaml:"add_request_id_header"`
}

type Rule struct {
	Name   string `yaml:"name"`
	Stage  string `yaml:"stage"`
	Action string `yaml:"action"`
	Match  Match  `yaml:"match"`
}

type Match struct {
	Pattern   string   `yaml:"pattern"`
	ToolNames []string `yaml:"tool_names"`
	Field     string   `yaml:"field"`
}

func Load(path string) (Config, error) {
	cfg := Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	applyDefaults(&cfg)
	if err := validate(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 1024 * 1024
	}
	if cfg.AuditLogPath == "" {
		cfg.AuditLogPath = "audit.jsonl"
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = time.RFC3339Nano
	}
	if cfg.Approval.TTL == 0 {
		cfg.Approval.TTL = 10 * time.Minute
	}
	if len(cfg.DecisionOrder) == 0 {
		cfg.DecisionOrder = []string{"deny", "approve", "allow"}
	}
}

func validate(cfg Config) error {
	if cfg.Upstream == "" {
		return errors.New("upstream is required")
	}
	for i, rule := range cfg.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d missing name", i)
		}
		if rule.Action == "" {
			return fmt.Errorf("rule %s missing action", rule.Name)
		}
		if rule.Stage == "" {
			return fmt.Errorf("rule %s missing stage", rule.Name)
		}
	}
	return nil
}
