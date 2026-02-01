package policy

import (
	"regexp"
	"strings"

	"prompt-injection-firewall/internal/config"
)

type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionApprove Decision = "approve"
)

type Result struct {
	Decision Decision
	RuleName string
	Reason   string
}

type Evaluator struct {
	rules []compiledRule
	order []Decision
}

type compiledRule struct {
	config.Rule
	pattern *regexp.Regexp
}

func NewEvaluator(rules []config.Rule, order []string) *Evaluator {
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		cr := compiledRule{Rule: rule}
		if rule.Match.Pattern != "" {
			cr.pattern = regexp.MustCompile(rule.Match.Pattern)
		}
		compiled = append(compiled, cr)
	}
	return &Evaluator{
		rules: compiled,
		order: parseOrder(order),
	}
}

func parseOrder(order []string) []Decision {
	out := make([]Decision, 0, len(order))
	for _, item := range order {
		switch strings.ToLower(item) {
		case string(DecisionDeny):
			out = append(out, DecisionDeny)
		case string(DecisionApprove):
			out = append(out, DecisionApprove)
		case string(DecisionAllow):
			out = append(out, DecisionAllow)
		}
	}
	if len(out) == 0 {
		out = []Decision{DecisionDeny, DecisionApprove, DecisionAllow}
	}
	return out
}

func (e *Evaluator) Evaluate(stage string, text string, toolNames []string) Result {
	stage = strings.ToLower(stage)
	for _, decision := range e.order {
		if res, ok := e.matchStage(stage, text, toolNames, decision); ok {
			return res
		}
	}
	return Result{Decision: DecisionAllow, Reason: "no_matching_rule"}
}

func (e *Evaluator) matchStage(stage string, text string, toolNames []string, decision Decision) (Result, bool) {
	for _, rule := range e.rules {
		if strings.ToLower(rule.Stage) != stage {
			continue
		}
		if strings.ToLower(rule.Action) != string(decision) {
			continue
		}
		if !matches(rule, text, toolNames) {
			continue
		}
		return Result{
			Decision: decision,
			RuleName: rule.Name,
			Reason:   "matched_rule",
		}, true
	}
	return Result{}, false
}

func matches(rule compiledRule, text string, toolNames []string) bool {
	if rule.Match.Pattern != "" && rule.pattern != nil {
		if !rule.pattern.MatchString(text) {
			return false
		}
	}
	if len(rule.Match.ToolNames) > 0 {
		if !hasAnyTool(toolNames, rule.Match.ToolNames) {
			return false
		}
	}
	return true
}

func hasAnyTool(tools []string, wanted []string) bool {
	lookup := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		lookup[strings.ToLower(tool)] = struct{}{}
	}
	for _, name := range wanted {
		if _, ok := lookup[strings.ToLower(name)]; ok {
			return true
		}
	}
	return false
}
