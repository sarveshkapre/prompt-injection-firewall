package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"prompt-injection-firewall/internal/audit"
	"prompt-injection-firewall/internal/config"
	"prompt-injection-firewall/internal/policy"
)

func TestProxyAllowForwardsToUpstream(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		if r.URL.Path != "/v1/chat" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	logger := newTempLogger(t)
	defer logger.Close()

	cfg := config.Config{
		ListenAddr:   ":0",
		Upstream:     upstream.URL,
		AuditLogPath: "audit.jsonl",
		MaxBodyBytes: 1024 * 1024,
		Rules: []config.Rule{
			{
				Name:   "allow_all",
				Stage:  "request",
				Action: "allow",
				Match:  config.Match{Pattern: ".*"},
			},
		},
	}
	cfg.DecisionOrder = []string{"allow"}
	server := New(cfg, policy.NewEvaluator(cfg.Rules, cfg.DecisionOrder), logger)
	proxyServer := httptest.NewServer(server)
	defer proxyServer.Close()

	payload := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	resp, err := http.Post(proxyServer.URL+"/v1/chat", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status: %d body=%s", resp.StatusCode, string(body))
	}
	if !upstreamCalled {
		t.Fatalf("expected upstream to be called")
	}
}

func TestProxyApproveFlow(t *testing.T) {
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	logger := newTempLogger(t)
	defer logger.Close()

	cfg := config.Config{
		ListenAddr:   ":0",
		Upstream:     upstream.URL,
		AuditLogPath: "audit.jsonl",
		MaxBodyBytes: 1024 * 1024,
		Approval: config.Approval{
			Enabled: true,
			Token:   "secret",
			TTL:     time.Minute,
		},
		Rules: []config.Rule{
			{
				Name:   "approve_tools",
				Stage:  "request",
				Action: "approve",
				Match:  config.Match{ToolNames: []string{"file_write"}},
			},
		},
	}
	cfg.DecisionOrder = []string{"approve"}
	server := New(cfg, policy.NewEvaluator(cfg.Rules, cfg.DecisionOrder), logger)
	proxyServer := httptest.NewServer(server)
	defer proxyServer.Close()

	payload := []byte(`{"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"file_write"}]}`)
	resp, err := http.Post(proxyServer.URL+"/v1/chat", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202, got %d body=%s", resp.StatusCode, string(body))
	}
	var approvalResp struct {
		ApprovalID string `json:"approval_id"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &approvalResp); err != nil || approvalResp.ApprovalID == "" {
		t.Fatalf("invalid approval response: %s", string(body))
	}

	approvePayload := []byte(`{"approval_id":"` + approvalResp.ApprovalID + `"}`)
	approveReq, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/approve", bytes.NewReader(approvePayload))
	approveReq.Header.Set("Content-Type", "application/json")
	approveReq.Header.Set("X-Approval-Token", "secret")
	approveResp, err := http.DefaultClient.Do(approveReq)
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	defer approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("unexpected approve status: %d body=%s", approveResp.StatusCode, string(respBody))
	}
	if string(upstreamBody) != string(payload) {
		t.Fatalf("unexpected upstream body: %s", string(upstreamBody))
	}
}

func newTempLogger(t *testing.T) *audit.Logger {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	_ = file.Close()
	logger, err := audit.NewLogger(file.Name())
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	return logger
}
