//go:build ignore

package main

import (
	"kit/ext"
	"strings"
)

func Init(api ext.API) {
	// Warn when writing files that may contain secrets
	api.OnToolCall(func(e ext.ToolCallEvent, ctx ext.Context) ext.ToolCallResult {
		if e.Name == "write" || e.Name == "edit" {
			secretPatterns := []string{
				"AKIA",          // AWS access key prefix
				"sk-",           // OpenAI/Stripe key prefix
				"ghp_",          // GitHub personal access token
				"gho_",          // GitHub OAuth token
				"password=",
				"passwd=",
				"secret=",
				"api_key=",
				"apikey=",
				"private_key",
			}
			for _, pattern := range secretPatterns {
				if strings.Contains(e.Args, pattern) {
					return ext.ToolCallResult{
						Block:   true,
						Message: "Blocked: potential secret/credential detected in file write: " + pattern,
					}
				}
			}
		}
		return ext.ToolCallResult{}
	})
}
