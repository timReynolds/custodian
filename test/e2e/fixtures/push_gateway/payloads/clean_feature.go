package payloads

import "fmt"

// FormatGreeting builds a benign greeting message for E2E clean-push tests.
func FormatGreeting(name string) string {
	if name == "" {
		return "hello, world"
	}
	return fmt.Sprintf("hello, %s", name)
}
