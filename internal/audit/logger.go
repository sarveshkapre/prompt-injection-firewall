package audit

import (
	"encoding/json"
	"os"
	"sync"
)

type Logger struct {
	mu   sync.Mutex
	file *os.File
}

type Event struct {
	Time        string   `json:"time"`
	RequestID   string   `json:"request_id"`
	RemoteAddr  string   `json:"remote_addr"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Decision    string   `json:"decision"`
	RuleName    string   `json:"rule_name,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	TextSample  string   `json:"text_sample,omitempty"`
	ToolNames   []string `json:"tool_names,omitempty"`
	Upstream    string   `json:"upstream"`
	ApprovalID  string   `json:"approval_id,omitempty"`
	ElapsedMS   int64    `json:"elapsed_ms"`
	StatusCode  int      `json:"status_code,omitempty"`
	BytesIn     int      `json:"bytes_in,omitempty"`
	BytesOut    int      `json:"bytes_out,omitempty"`
	ErrorString string   `json:"error,omitempty"`
}

func NewLogger(path string) (*Logger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{file: file}, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *Logger) Write(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = l.file.Write(data)
	return err
}
