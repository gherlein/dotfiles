//go:build ignore

package main

import "kit/ext"

func Init(api ext.API) {
	// Block destructive operations without confirmation
	api.OnToolCall(func(e ext.ToolCallEvent, ctx ext.Context) ext.ToolCallResult {
		if e.Name == "bash" {
			dangerous := []string{
				"rm -rf",
				"DROP TABLE",
				"DROP DATABASE",
				"DELETE FROM",
				"TRUNCATE",
				"chmod 777",
				"dd if=",
				"mkfs",
				"> /dev/",
				":(){ :|:&",
				"git push --force",
				"git reset --hard",
				"git clean -f",
			}
			for _, pattern := range dangerous {
				if containsPattern(e.Args, pattern) {
					return ext.ToolCallResult{
						Block:   true,
						Message: "Blocked: destructive command detected: " + pattern,
					}
				}
			}
		}
		return ext.ToolCallResult{}
	})
}

func containsPattern(args, pattern string) bool {
	return len(args) >= len(pattern) && searchString(args, pattern)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
