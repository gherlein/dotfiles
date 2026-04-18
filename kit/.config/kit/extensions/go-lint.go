//go:build ignore

package main

import (
	"kit/ext"
	"strings"
)

func Init(api ext.API) {
	// Remind to run go vet after editing Go files
	api.OnToolExecutionEnd(func(e ext.ToolExecutionEndEvent, ctx ext.Context) {
		if e.Name == "edit" || e.Name == "write" {
			if strings.HasSuffix(e.Args, ".go") {
				ctx.Print("Go file modified. Run `go vet ./...` to check for issues.")
			}
		}
	})
}
