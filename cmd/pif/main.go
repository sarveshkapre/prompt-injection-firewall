package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"prompt-injection-firewall/internal/audit"
	"prompt-injection-firewall/internal/config"
	"prompt-injection-firewall/internal/policy"
	"prompt-injection-firewall/internal/proxy"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	logger, err := audit.NewLogger(cfg.AuditLogPath)
	if err != nil {
		log.Fatalf("failed to open audit log: %v", err)
	}
	defer func() {
		_ = logger.Close()
	}()

	evaluator := policy.NewEvaluator(cfg.Rules, cfg.DecisionOrder)
	server := proxy.New(cfg, evaluator, logger)

	log.Printf("prompt-injection-firewall listening on %s", cfg.ListenAddr)
	log.Printf("upstream: %s", cfg.Upstream)
	if cfg.Approval.Enabled {
		log.Printf("approval endpoint enabled: /approve")
	}
	if cfg.Approval.Token == "" && cfg.Approval.Enabled {
		fmt.Fprintln(os.Stderr, "warning: approval endpoint enabled without token")
	}

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: server,
	}

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
