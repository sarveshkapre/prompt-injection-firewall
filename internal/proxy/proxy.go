package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"prompt-injection-firewall/internal/audit"
	"prompt-injection-firewall/internal/config"
	"prompt-injection-firewall/internal/extract"
	"prompt-injection-firewall/internal/policy"
)

type Server struct {
	cfg       config.Config
	evaluator *policy.Evaluator
	logger    *audit.Logger
	client    *http.Client
	pending   *approvalStore
}

type approvalStore struct {
	mu    sync.Mutex
	items map[string]pendingRequest
	ttl   time.Duration
}

type pendingRequest struct {
	method  string
	path    string
	header  http.Header
	body    []byte
	created time.Time
}

func New(cfg config.Config, evaluator *policy.Evaluator, logger *audit.Logger) *Server {
	return &Server{
		cfg:       cfg,
		evaluator: evaluator,
		logger:    logger,
		client:    &http.Client{Timeout: 60 * time.Second},
		pending: &approvalStore{
			items: make(map[string]pendingRequest),
			ttl:   cfg.Approval.TTL,
		},
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/approve" {
		s.handleApprove(w, r)
		return
	}
	start := time.Now()
	requestID := newID()
	body, err := readBody(r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large")
		s.logEvent(audit.Event{
			Time:       time.Now().Format(s.cfg.TimeFormat),
			RequestID:  requestID,
			RemoteAddr: r.RemoteAddr,
			Method:     r.Method,
			Path:       r.URL.Path,
			Decision:   string(policy.DecisionDeny),
			Reason:     "body_too_large",
			Upstream:   s.cfg.Upstream,
			ElapsedMS:  elapsedMS(start),
			BytesIn:    len(body),
			StatusCode: http.StatusRequestEntityTooLarge,
		})
		return
	}
	text, toolNames, decision, ruleName, reason := s.inspect(body)
	if decision == policy.DecisionDeny {
		writeError(w, http.StatusForbidden, "blocked")
		s.logEvent(audit.Event{
			Time:       time.Now().Format(s.cfg.TimeFormat),
			RequestID:  requestID,
			RemoteAddr: r.RemoteAddr,
			Method:     r.Method,
			Path:       r.URL.Path,
			Decision:   string(decision),
			RuleName:   ruleName,
			Reason:     reason,
			TextSample: sample(text),
			ToolNames:  toolNames,
			Upstream:   s.cfg.Upstream,
			ElapsedMS:  elapsedMS(start),
			BytesIn:    len(body),
			StatusCode: http.StatusForbidden,
		})
		return
	}
	if decision == policy.DecisionApprove {
		if !s.cfg.Approval.Enabled {
			writeError(w, http.StatusForbidden, "approval_disabled")
			s.logEvent(audit.Event{
				Time:       time.Now().Format(s.cfg.TimeFormat),
				RequestID:  requestID,
				RemoteAddr: r.RemoteAddr,
				Method:     r.Method,
				Path:       r.URL.Path,
				Decision:   string(policy.DecisionDeny),
				RuleName:   ruleName,
				Reason:     "approval_disabled",
				TextSample: sample(text),
				ToolNames:  toolNames,
				Upstream:   s.cfg.Upstream,
				ElapsedMS:  elapsedMS(start),
				BytesIn:    len(body),
				StatusCode: http.StatusForbidden,
			})
			return
		}
		approvalID := s.pending.store(pendingRequest{
			method:  r.Method,
			path:    r.URL.RequestURI(),
			header:  cloneHeader(r.Header),
			body:    body,
			created: time.Now(),
		})
		writeJSON(w, http.StatusAccepted, map[string]string{
			"approval_id": approvalID,
			"status":      "approval_required",
		})
		s.logEvent(audit.Event{
			Time:       time.Now().Format(s.cfg.TimeFormat),
			RequestID:  requestID,
			RemoteAddr: r.RemoteAddr,
			Method:     r.Method,
			Path:       r.URL.Path,
			Decision:   string(decision),
			RuleName:   ruleName,
			Reason:     reason,
			TextSample: sample(text),
			ToolNames:  toolNames,
			Upstream:   s.cfg.Upstream,
			ApprovalID: approvalID,
			ElapsedMS:  elapsedMS(start),
			BytesIn:    len(body),
			StatusCode: http.StatusAccepted,
		})
		return
	}
	resp, err := s.forward(r, body, requestID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error")
		s.logEvent(audit.Event{
			Time:        time.Now().Format(s.cfg.TimeFormat),
			RequestID:   requestID,
			RemoteAddr:  r.RemoteAddr,
			Method:      r.Method,
			Path:        r.URL.Path,
			Decision:    string(decision),
			RuleName:    ruleName,
			Reason:      err.Error(),
			TextSample:  sample(text),
			ToolNames:   toolNames,
			Upstream:    s.cfg.Upstream,
			ElapsedMS:   elapsedMS(start),
			BytesIn:     len(body),
			StatusCode:  http.StatusBadGateway,
			ErrorString: err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	bytesOut, _ := io.Copy(w, resp.Body)
	s.logEvent(audit.Event{
		Time:       time.Now().Format(s.cfg.TimeFormat),
		RequestID:  requestID,
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
		Decision:   string(decision),
		RuleName:   ruleName,
		Reason:     reason,
		TextSample: sample(text),
		ToolNames:  toolNames,
		Upstream:   s.cfg.Upstream,
		ElapsedMS:  elapsedMS(start),
		BytesIn:    len(body),
		BytesOut:   int(bytesOut),
		StatusCode: resp.StatusCode,
	})
}

func (s *Server) inspect(body []byte) (string, []string, policy.Decision, string, string) {
	result, err := extract.FromJSON(body)
	if err != nil {
		return "", nil, policy.DecisionDeny, "", "invalid_json"
	}
	res := s.evaluator.Evaluate("request", result.Text, result.ToolNames)
	return result.Text, result.ToolNames, res.Decision, res.RuleName, res.Reason
}

func (s *Server) forward(r *http.Request, body []byte, requestID string) (*http.Response, error) {
	upstreamURL, err := url.Parse(s.cfg.Upstream)
	if err != nil {
		return nil, err
	}
	target := *upstreamURL
	target.Path = joinPaths(upstreamURL.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery
	req, err := http.NewRequest(r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyHeaders(req.Header, r.Header)
	removeHopHeaders(req.Header)
	if s.cfg.Headers.AddRequestIDHeader {
		req.Header.Set("X-Request-ID", requestID)
	}
	addForwardedFor(req, r.RemoteAddr)
	return s.client.Do(req)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Approval.Enabled {
		writeError(w, http.StatusNotFound, "approval_disabled")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if s.cfg.Approval.Token != "" {
		if r.Header.Get("X-Approval-Token") != s.cfg.Approval.Token {
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
	}
	body, err := readBody(r, 1024*16)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	var payload struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.ApprovalID == "" {
		writeError(w, http.StatusBadRequest, "invalid_approval_id")
		return
	}
	pending, ok := s.pending.fetch(payload.ApprovalID)
	if !ok {
		writeError(w, http.StatusNotFound, "approval_not_found")
		return
	}
	start := time.Now()
	req, err := http.NewRequest(pending.method, s.cfg.Upstream+pending.path, bytes.NewReader(pending.body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error")
		return
	}
	copyHeaders(req.Header, pending.header)
	removeHopHeaders(req.Header)
	resp, err := s.client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error")
		s.logEvent(audit.Event{
			Time:        time.Now().Format(s.cfg.TimeFormat),
			Decision:    string(policy.DecisionApprove),
			RuleName:    "approval_handler",
			Reason:      err.Error(),
			Upstream:    s.cfg.Upstream,
			ApprovalID:  payload.ApprovalID,
			ElapsedMS:   elapsedMS(start),
			StatusCode:  http.StatusBadGateway,
			ErrorString: err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	s.logEvent(audit.Event{
		Time:       time.Now().Format(s.cfg.TimeFormat),
		Decision:   string(policy.DecisionApprove),
		RuleName:   "approval_handler",
		Reason:     "approved_request",
		Upstream:   s.cfg.Upstream,
		ApprovalID: payload.ApprovalID,
		ElapsedMS:  elapsedMS(start),
		StatusCode: resp.StatusCode,
	})
}

func (s *Server) logEvent(event audit.Event) {
	if s.logger == nil {
		return
	}
	_ = s.logger.Write(event)
}

func (s *approvalStore) store(req pendingRequest) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	id := newID()
	s.items[id] = req
	return id
}

func (s *approvalStore) fetch(id string) (pendingRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.items[id]
	if !ok {
		return pendingRequest{}, false
	}
	if time.Since(req.created) > s.ttl {
		delete(s.items, id)
		return pendingRequest{}, false
	}
	delete(s.items, id)
	return req, true
}

func (s *approvalStore) cleanupLocked() {
	if len(s.items) == 0 {
		return
	}
	for id, req := range s.items {
		if time.Since(req.created) > s.ttl {
			delete(s.items, id)
		}
	}
}

func readBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return data[:limit], errors.New("body too large")
	}
	return data, nil
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{
		"error": message,
	})
}

func writeJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	data, _ := json.Marshal(payload)
	_, _ = w.Write(data)
}

func addForwardedFor(req *http.Request, remoteAddr string) {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	existing := req.Header.Get("X-Forwarded-For")
	if existing == "" {
		req.Header.Set("X-Forwarded-For", ip)
		return
	}
	req.Header.Set("X-Forwarded-For", existing+", "+ip)
}

func cloneHeader(header http.Header) http.Header {
	copy := make(http.Header, len(header))
	for key, values := range header {
		clone := make([]string, len(values))
		copySlice(clone, values)
		copy[key] = clone
	}
	return copy
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func copySlice(dst, src []string) {
	for i, value := range src {
		dst[i] = value
	}
}

func removeHopHeaders(header http.Header) {
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade"} {
		header.Del(key)
	}
}

func sample(text string) string {
	if len(text) <= 200 {
		return text
	}
	return text[:200]
}

func elapsedMS(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func joinPaths(basePath, path string) string {
	if basePath == "" || basePath == "/" {
		return path
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(path, "/")
}
