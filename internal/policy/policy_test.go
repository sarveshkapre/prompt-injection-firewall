package policy

import (
	"testing"

	"prompt-injection-firewall/internal/config"
)

func TestEvaluatorOrder(t *testing.T) {
	rules := []config.Rule{
		{
			Name:   "allow_all",
			Stage:  "request",
			Action: "allow",
			Match:  config.Match{Pattern: ".*"},
		},
		{
			Name:   "deny_secret",
			Stage:  "request",
			Action: "deny",
			Match:  config.Match{Pattern: "secret"},
		},
	}
	eval := NewEvaluator(rules, []string{"deny", "allow"})
	res := eval.Evaluate("request", "contains secret", nil)
	if res.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
}

func TestEvaluatorToolMatch(t *testing.T) {
	rules := []config.Rule{
		{
			Name:   "approve_tools",
			Stage:  "request",
			Action: "approve",
			Match:  config.Match{ToolNames: []string{"file_write"}},
		},
	}
	eval := NewEvaluator(rules, []string{"approve"})
	res := eval.Evaluate("request", "", []string{"file_write"})
	if res.Decision != DecisionApprove {
		t.Fatalf("expected approve, got %s", res.Decision)
	}
}
