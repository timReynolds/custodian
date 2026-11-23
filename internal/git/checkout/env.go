package checkout

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	urlUserInfoPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@]+)@`)
	tokenPatterns      = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`),
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`x-access-token:[^\s@'"]+`),
	}
)

// HardenedGitFlags returns mandatory -c flags that disable hooks, symlinks, fsmonitor,
// credential helpers, submodule recursion, and unsafe transport protocols.
func HardenedGitFlags(allowLocalBare bool) []string {
	fileAllow := "never"
	if allowLocalBare {
		fileAllow = "always"
	}
	return []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.symlinks=false",
		"-c", "core.fsmonitor=false",
		"-c", "core.autocrlf=false",
		"-c", "credential.helper=",
		"-c", "submodule.recurse=false",
		"-c", "fetch.fsckObjects=true",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=" + fileAllow,
	}
}

// CleanGitEnv constructs a minimal isolated environment for native git invocations,
// stripping all inherited GIT_*, SSH_ASKPASS, LD_*, and DYLD_* variables.
func CleanGitEnv(homeDir string, allowLocalBare, allowInsecureHTTP bool, askpassPath, tokenFilePath string) []string {
	allowedKeys := map[string]struct{}{
		"PATH":          {},
		"TMPDIR":        {},
		"LANG":          {},
		"LC_ALL":        {},
		"SSL_CERT_FILE": {},
		"SSL_CERT_DIR":  {},
	}

	env := make([]string, 0, 16)
	for _, entry := range os.Environ() {
		k, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, keep := allowedKeys[k]; keep {
			env = append(env, entry)
		}
	}

	allowProtocol := "https"
	if allowLocalBare {
		allowProtocol = "file"
	} else if allowInsecureHTTP {
		allowProtocol = "https:http"
	}

	env = append(env,
		"HOME="+homeDir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL="+allowProtocol,
	)

	if askpassPath != "" && tokenFilePath != "" {
		env = append(env,
			"GIT_ASKPASS="+askpassPath,
			"CUSTODIAN_TOKEN_FILE="+tokenFilePath,
		)
	}
	return env
}

// PrepareAskpass creates an isolated 0700 directory with a 0600 token file and 0700 askpass helper script.
func PrepareAskpass(token string) (askpassPath, tokenFilePath string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "custodian-askpass-*")
	if err != nil {
		return "", "", nil, fmt.Errorf("create askpass dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", nil, fmt.Errorf("chmod askpass dir: %w", err)
	}
	cleanupFn := func() {
		_ = os.RemoveAll(dir)
	}

	tokenFilePath = filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFilePath, []byte(token+"\n"), 0o600); err != nil {
		cleanupFn()
		return "", "", nil, fmt.Errorf("write askpass token file: %w", err)
	}

	askpassPath = filepath.Join(dir, "askpass.sh")
	script := "#!/bin/sh\ncase \"$1\" in\n  *Username*|*username*) printf '%s\\n' 'x-access-token' ;;\n  *) cat \"$CUSTODIAN_TOKEN_FILE\" ;;\nesac\n"
	if err := os.WriteFile(askpassPath, []byte(script), 0o700); err != nil {
		cleanupFn()
		return "", "", nil, fmt.Errorf("write askpass script: %w", err)
	}
	return askpassPath, tokenFilePath, cleanupFn, nil
}

// SanitizeGitOutput strips credentials, tokens, and URL userinfo from git stderr/stdout before surfacing errors.
func SanitizeGitOutput(raw string, secrets ...string) string {
	out := strings.TrimSpace(raw)
	for _, s := range secrets {
		if s != "" {
			out = strings.ReplaceAll(out, s, "[REDACTED]")
		}
	}
	out = urlUserInfoPattern.ReplaceAllString(out, "${1}[REDACTED]@")
	for _, pat := range tokenPatterns {
		out = pat.ReplaceAllString(out, "[REDACTED]")
	}
	if len(out) > 512 {
		out = out[:512] + "...[truncated]"
	}
	return out
}
