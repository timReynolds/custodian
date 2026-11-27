package harness

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// SSHUserCertSpec configures an OpenSSH user certificate minted by SSHCAHelper.
type SSHUserCertSpec struct {
	KeyID      string
	Principals []string
	Validity   string // OpenSSH -V specification, e.g. "-5m:+1h" or "-2h:-1h"
	UseRogueCA bool
	Serial     uint64
}

// SSHUserCredential holds the generated Ed25519 user keypair, signed OpenSSH certificate,
// and helpers to construct hardened GIT_SSH_COMMAND invocations.
type SSHUserCredential struct {
	PrivateKeyPath string
	PubKeyPath     string
	CertPath       string
	Principal      string
	Principals     []string
	KeyID          string
	Validity       string

	helper *SSHCAHelper
}

// GitSSHCommand returns a hardened GIT_SSH_COMMAND targeting port on 127.0.0.1/localhost
// using a known_hosts file populated by SSHCAHelper.
func (c SSHUserCredential) GitSSHCommand(port int) string {
	if c.helper == nil {
		return ""
	}
	if port <= 0 {
		c.helper.t.Fatalf("SSHUserCredential.GitSSHCommand: port must be > 0, got %d", port)
	}
	return c.helper.GitSSHCommand(c, fmt.Sprintf("127.0.0.1:%d", port))
}

// GitSSHCommandForAddr returns a hardened GIT_SSH_COMMAND targeting sshAddr (host:port)
// using a known_hosts file populated by SSHCAHelper.
func (c SSHUserCredential) GitSSHCommandForAddr(sshAddr string) string {
	if c.helper == nil {
		return ""
	}
	return c.helper.GitSSHCommand(c, sshAddr)
}

type sshCAConfig struct {
	rootDir  string
	onSecret func(string)
}

// SSHCAOption configures NewSSHCAHelper.
type SSHCAOption func(*sshCAConfig)

// WithSSHRootDir sets the directory used to store generated SSH keys, CAs, certs, and known_hosts files.
func WithSSHRootDir(dir string) SSHCAOption {
	return func(c *sshCAConfig) {
		if dir != "" {
			c.rootDir = dir
		}
	}
}

// WithSSHSecretRecorder registers a callback invoked with every generated private key PEM/OpenSSH string.
func WithSSHSecretRecorder(fn func(string)) SSHCAOption {
	return func(c *sshCAConfig) {
		if fn != nil {
			c.onSecret = fn
		}
	}
}

// SSHCAHelper manages an ephemeral Ed25519 SSH host key, legitimate User CA, Rogue CA,
// and minted user certificates via /usr/bin/ssh-keygen using Go stdlib only.
type SSHCAHelper struct {
	t             testing.TB
	rootDir       string
	keygenBin     string
	hostKeyPath   string
	hostPubPath   string
	userCAKeyPath string
	userCAPubPath string
	rogueCAKey    string
	rogueCAPub    string

	seq        atomic.Int64
	mu         sync.Mutex
	secrets    []string
	onSecret   func(string)
	knownHosts map[string]string
}

func resolveSSHKeygenBin() (string, error) {
	if info, err := os.Stat("/usr/bin/ssh-keygen"); err == nil && !info.IsDir() {
		return "/usr/bin/ssh-keygen", nil
	}
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return "", fmt.Errorf("ssh-keygen not found in /usr/bin or PATH: %w", err)
	}
	return p, nil
}

// NewSSHCAHelper creates an isolated OpenSSH CA and host key helper.
func NewSSHCAHelper(t testing.TB, opts ...SSHCAOption) *SSHCAHelper {
	t.Helper()

	cfg := sshCAConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	keygenBin, err := resolveSSHKeygenBin()
	if err != nil {
		t.Fatalf("NewSSHCAHelper: %v", err)
	}

	rootDir := cfg.rootDir
	if rootDir == "" {
		rootDir = filepath.Join(t.TempDir(), "ssh-ca")
	}
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		t.Fatalf("mkdir ssh-ca root %q: %v", rootDir, err)
	}

	h := &SSHCAHelper{
		t:             t,
		rootDir:       rootDir,
		keygenBin:     keygenBin,
		hostKeyPath:   filepath.Join(rootDir, "host_ed25519"),
		hostPubPath:   filepath.Join(rootDir, "host_ed25519.pub"),
		userCAKeyPath: filepath.Join(rootDir, "user_ca_ed25519"),
		userCAPubPath: filepath.Join(rootDir, "user_ca_ed25519.pub"),
		rogueCAKey:    filepath.Join(rootDir, "rogue_ca_ed25519"),
		rogueCAPub:    filepath.Join(rootDir, "rogue_ca_ed25519.pub"),
		onSecret:      cfg.onSecret,
		knownHosts:    make(map[string]string),
	}

	if err := h.generateEd25519Keypair(h.hostKeyPath, "custodian-e2e-host"); err != nil {
		t.Fatalf("generate SSH host key: %v", err)
	}
	if err := h.generateEd25519Keypair(h.userCAKeyPath, "custodian-e2e-user-ca"); err != nil {
		t.Fatalf("generate SSH User CA key: %v", err)
	}
	if err := h.generateEd25519Keypair(h.rogueCAKey, "custodian-e2e-rogue-ca"); err != nil {
		t.Fatalf("generate SSH Rogue CA key: %v", err)
	}

	return h
}

func (h *SSHCAHelper) generateEd25519Keypair(privPath, comment string) error {
	_ = os.Remove(privPath)
	_ = os.Remove(privPath + ".pub")

	cmd := exec.Command(h.keygenBin, "-t", "ed25519", "-N", "", "-f", privPath, "-C", comment, "-q")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen keypair %q: %w (%s)", privPath, err, strings.TrimSpace(out.String()))
	}
	if err := os.Chmod(privPath, 0o600); err != nil {
		return fmt.Errorf("chmod 0600 %q: %w", privPath, err)
	}
	raw, err := os.ReadFile(privPath)
	if err != nil {
		return fmt.Errorf("read private key %q: %w", privPath, err)
	}
	h.recordSecret(string(raw))
	return nil
}

func (h *SSHCAHelper) recordSecret(sec string) {
	if sec == "" {
		return
	}
	h.mu.Lock()
	h.secrets = append(h.secrets, sec)
	cb := h.onSecret
	h.mu.Unlock()
	if cb != nil {
		cb(sec)
	}
}

func (h *SSHCAHelper) HostKeyPath() string      { return h.hostKeyPath }
func (h *SSHCAHelper) HostPubKeyPath() string   { return h.hostPubPath }
func (h *SSHCAHelper) UserCAPubKeyPath() string { return h.userCAPubPath }
func (h *SSHCAHelper) RogueCAPubKeyPath() string {
	return h.rogueCAPub
}

func (h *SSHCAHelper) UserCAPubKey() (string, error) {
	data, err := os.ReadFile(h.userCAPubPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (h *SSHCAHelper) HostPubKey() (string, error) {
	data, err := os.ReadFile(h.hostPubPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// Secrets returns a copy of all private key contents recorded by this helper.
func (h *SSHCAHelper) Secrets() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.secrets))
	copy(out, h.secrets)
	return out
}

// RegisterSecrets invokes reg for all previously recorded private key secrets
// and sets reg as the recorder for future minted keys if none was set.
func (h *SSHCAHelper) RegisterSecrets(reg func(string)) {
	if reg == nil {
		return
	}
	h.mu.Lock()
	if h.onSecret == nil {
		h.onSecret = reg
	}
	cp := make([]string, len(h.secrets))
	copy(cp, h.secrets)
	h.mu.Unlock()

	for _, s := range cp {
		reg(s)
	}
}

// MintUserCert generates a fresh Ed25519 user keypair and signs an OpenSSH user certificate.
func (h *SSHCAHelper) MintUserCert(spec SSHUserCertSpec) SSHUserCredential {
	h.t.Helper()
	seq := h.seq.Add(1)
	keyPath := filepath.Join(h.rootDir, fmt.Sprintf("user_%d_ed25519", seq))
	pubPath := keyPath + ".pub"
	certPath := keyPath + "-cert.pub"

	keyID := strings.TrimSpace(spec.KeyID)
	if keyID == "" {
		keyID = fmt.Sprintf("e2e-user-%d", seq)
	}
	validity := strings.TrimSpace(spec.Validity)
	if validity == "" {
		validity = "-5m:+1h"
	}

	if err := h.generateEd25519Keypair(keyPath, keyID); err != nil {
		h.t.Fatalf("MintUserCert generate keypair: %v", err)
	}

	caKey := h.userCAKeyPath
	if spec.UseRogueCA {
		caKey = h.rogueCAKey
	}

	args := []string{"-s", caKey, "-I", keyID, "-V", validity}
	if spec.Serial > 0 {
		args = append(args, "-z", strconv.FormatUint(spec.Serial, 10))
	}
	var principalsCopy []string
	for _, p := range spec.Principals {
		p = strings.TrimSpace(p)
		if p != "" {
			principalsCopy = append(principalsCopy, p)
		}
	}
	if len(principalsCopy) > 0 {
		args = append(args, "-n", strings.Join(principalsCopy, ","))
	}
	args = append(args, pubPath)

	cmd := exec.Command(h.keygenBin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("ssh-keygen sign cert %v: %v (%s)", args, err, strings.TrimSpace(out.String()))
	}
	if _, err := os.Stat(certPath); err != nil {
		h.t.Fatalf("expected minted cert file %q: %v", certPath, err)
	}

	primaryPrincipal := ""
	if len(principalsCopy) > 0 {
		primaryPrincipal = principalsCopy[0]
	}

	return SSHUserCredential{
		PrivateKeyPath: keyPath,
		PubKeyPath:     pubPath,
		CertPath:       certPath,
		Principal:      primaryPrincipal,
		Principals:     principalsCopy,
		KeyID:          keyID,
		Validity:       validity,
		helper:         h,
	}
}

// MintValidCert mints a currently-valid OpenSSH user certificate signed by the legitimate User CA.
func (h *SSHCAHelper) MintValidCert(keyID string, principals []string) SSHUserCredential {
	h.t.Helper()
	return h.MintUserCert(SSHUserCertSpec{
		KeyID:      keyID,
		Principals: principals,
		Validity:   "-5m:+1h",
	})
}

// MintExpiredCert mints an expired OpenSSH user certificate signed by the legitimate User CA.
func (h *SSHCAHelper) MintExpiredCert(keyID string, principals []string) SSHUserCredential {
	h.t.Helper()
	return h.MintUserCert(SSHUserCertSpec{
		KeyID:      keyID,
		Principals: principals,
		Validity:   "-2h:-1h",
	})
}

// MintWrongCACert mints a valid-window OpenSSH user certificate signed by the untrusted Rogue CA.
func (h *SSHCAHelper) MintWrongCACert(keyID string, principals []string) SSHUserCredential {
	h.t.Helper()
	return h.MintUserCert(SSHUserCertSpec{
		KeyID:      keyID,
		Principals: principals,
		Validity:   "-5m:+1h",
		UseRogueCA: true,
	})
}

// MintWrongPrincipalCert mints a valid-window OpenSSH user certificate with mismatched principals.
func (h *SSHCAHelper) MintWrongPrincipalCert(keyID string, wrongPrincipals []string) SSHUserCredential {
	h.t.Helper()
	return h.MintUserCert(SSHUserCertSpec{
		KeyID:      keyID,
		Principals: wrongPrincipals,
		Validity:   "-5m:+1h",
	})
}

// WriteKnownHosts creates (or reuses) a known_hosts file pinning the helper's host public key for sshAddr.
func (h *SSHCAHelper) WriteKnownHosts(sshAddr string) (string, error) {
	sshAddr = strings.TrimSpace(sshAddr)
	if sshAddr == "" {
		return "", fmt.Errorf("sshAddr must not be empty")
	}
	host, port, err := net.SplitHostPort(sshAddr)
	if err != nil {
		return "", fmt.Errorf("split sshAddr %q: %w", sshAddr, err)
	}
	hostPub, err := h.HostPubKey()
	if err != nil {
		return "", fmt.Errorf("read host public key: %w", err)
	}

	cacheKey := host + ":" + port
	h.mu.Lock()
	if existing, ok := h.knownHosts[cacheKey]; ok {
		if _, statErr := os.Stat(existing); statErr == nil {
			h.mu.Unlock()
			return existing, nil
		}
	}
	h.mu.Unlock()

	var lines []string
	seen := make(map[string]struct{})
	addEntry := func(hName string) {
		if hName == "" {
			return
		}
		var target string
		if port == "22" {
			target = hName
		} else {
			target = fmt.Sprintf("[%s]:%s", hName, port)
		}
		if _, dup := seen[target]; dup {
			return
		}
		seen[target] = struct{}{}
		lines = append(lines, fmt.Sprintf("%s %s", target, hostPub))
	}

	addEntry(host)
	addEntry("127.0.0.1")
	addEntry("localhost")

	khPath := filepath.Join(h.rootDir, fmt.Sprintf("known_hosts_%d", h.seq.Add(1)))
	if err := os.WriteFile(khPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write known_hosts %q: %w", khPath, err)
	}

	h.mu.Lock()
	h.knownHosts[cacheKey] = khPath
	h.mu.Unlock()
	return khPath, nil
}

// GitSSHCommand returns a hardened GIT_SSH_COMMAND pinning CertificateFile, IdentitiesOnly, and UserKnownHostsFile.
func (h *SSHCAHelper) GitSSHCommand(cred SSHUserCredential, sshAddr string) string {
	h.t.Helper()
	khPath, err := h.WriteKnownHosts(sshAddr)
	if err != nil {
		h.t.Fatalf("GitSSHCommand WriteKnownHosts(%q): %v", sshAddr, err)
	}
	_, port, err := net.SplitHostPort(sshAddr)
	if err != nil {
		h.t.Fatalf("GitSSHCommand SplitHostPort(%q): %v", sshAddr, err)
	}
	parts := []string{
		"ssh",
		"-p", port,
		"-i", shellQuote(cred.PrivateKeyPath),
		"-o", shellQuote(fmt.Sprintf(`CertificateFile="%s"`, cred.CertPath)),
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", shellQuote(fmt.Sprintf(`UserKnownHostsFile="%s"`, khPath)),
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "GSSAPIAuthentication=no",
		"-o", "ControlMaster=no",
	}
	return strings.Join(parts, " ")
}

// GitEnv returns an environment map containing GIT_SSH_COMMAND for cred against sshAddr.
func (h *SSHCAHelper) GitEnv(cred SSHUserCredential, sshAddr string) map[string]string {
	h.t.Helper()
	return map[string]string{
		"GIT_SSH_COMMAND": h.GitSSHCommand(cred, sshAddr),
	}
}
