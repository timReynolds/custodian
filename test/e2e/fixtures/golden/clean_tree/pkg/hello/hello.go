package hello

// Greeting returns a deterministic greeting for E2E golden verification.
func Greeting(name string) string {
	if name == "" {
		return "hello, custodian"
	}
	return "hello, " + name
}
