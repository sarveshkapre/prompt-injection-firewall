package extract

import (
	"encoding/json"
	"fmt"
)

type Result struct {
	Text      string
	ToolNames []string
}

func FromJSON(body []byte) (Result, error) {
	var raw interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Result{}, err
	}
	root, ok := raw.(map[string]interface{})
	if !ok {
		return Result{}, fmt.Errorf("json root not object")
	}
	text := collectText(root)
	tools := collectTools(root)
	return Result{Text: text, ToolNames: tools}, nil
}

func collectText(root map[string]interface{}) string {
	parts := []string{}
	if input, ok := root["input"]; ok {
		parts = append(parts, readInputField(input)...)
	}
	if messages, ok := root["messages"]; ok {
		parts = append(parts, readMessages(messages)...)
	}
	if prompt, ok := root["prompt"]; ok {
		parts = append(parts, readPrompt(prompt)...)
	}
	return join(parts)
}

func collectTools(root map[string]interface{}) []string {
	var out []string
	out = append(out, readTools(root["tools"])...)
	out = append(out, readTools(root["functions"])...)
	return dedupe(out)
}

func readInputField(input interface{}) []string {
	switch val := input.(type) {
	case string:
		return []string{val}
	case []interface{}:
		return readArrayText(val)
	case map[string]interface{}:
		return readContent(val)
	default:
		return nil
	}
}

func readMessages(messages interface{}) []string {
	arr, ok := messages.([]interface{})
	if !ok {
		return nil
	}
	return readArrayText(arr)
}

func readPrompt(prompt interface{}) []string {
	switch val := prompt.(type) {
	case string:
		return []string{val}
	case []interface{}:
		return readArrayStrings(val)
	default:
		return nil
	}
}

func readArrayText(arr []interface{}) []string {
	var out []string
	for _, item := range arr {
		switch val := item.(type) {
		case string:
			out = append(out, val)
		case map[string]interface{}:
			out = append(out, readContent(val)...)
		}
	}
	return out
}

func readArrayStrings(arr []interface{}) []string {
	var out []string
	for _, item := range arr {
		if str, ok := item.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

func readContent(obj map[string]interface{}) []string {
	var out []string
	if content, ok := obj["content"]; ok {
		switch val := content.(type) {
		case string:
			out = append(out, val)
		case []interface{}:
			out = append(out, readContentArray(val)...)
		}
	}
	if text, ok := obj["text"]; ok {
		if str, ok := text.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

func readContentArray(arr []interface{}) []string {
	var out []string
	for _, item := range arr {
		if obj, ok := item.(map[string]interface{}); ok {
			if text, ok := obj["text"]; ok {
				if str, ok := text.(string); ok {
					out = append(out, str)
				}
			}
		}
	}
	return out
}

func readTools(field interface{}) []string {
	arr, ok := field.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := obj["name"]; ok {
			if str, ok := name.(string); ok {
				out = append(out, str)
			}
		}
	}
	return out
}

func dedupe(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func join(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "\n" + parts[i]
	}
	return out
}
