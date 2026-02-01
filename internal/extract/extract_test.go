package extract

import "testing"

func TestExtractFromMessagesAndTools(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user", "content": "hello"},
			{"role": "user", "content": [{"type": "text", "text": "world"}]}
		],
		"tools": [{"name": "file_write"}, {"name": "exec_command"}]
	}`)
	res, err := FromJSON(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Text != "hello\nworld" {
		t.Fatalf("unexpected text: %s", res.Text)
	}
	if len(res.ToolNames) != 2 {
		t.Fatalf("expected 2 tool names, got %d", len(res.ToolNames))
	}
}
