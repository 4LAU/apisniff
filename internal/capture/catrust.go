package capture

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// caCommonName is the Subject CommonName of the proxy CA minted by
// generateProxyCA. It identifies the cert in the OS trust store.
const caCommonName = "apisniff local MITM CA"

// EnsureCATrusted makes the proxy CA trusted at the OS level so Chrome accepts
// the MITM leaf certificates natively — without the
// --ignore-certificate-errors-spki-list flag that triggers Chrome's
// "unsupported flag" warning bar. It returns true when the CA is trusted after
// the call; the caller then launches with no flag (and no warning).
//
// Only macOS is wired up today. On other platforms it returns false and the
// caller falls back to the flag, so capture still works there. Trust is added
// to the user's login keychain: no admin rights, just a one-time macOS
// authorization prompt. This is security-sensitive — a trusted root means
// anything holding the CA private key (~/.apisniff/ca-key.pem) could forge
// HTTPS certificates this machine trusts.
func EnsureCATrusted(caPath string, status io.Writer) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if caTrustedDarwin() {
		return true
	}
	if status != nil {
		fmt.Fprintf(status, "Trusting apisniff's certificate (one-time; approve the macOS prompt)...\n")
	}
	if err := trustCADarwin(caPath); err != nil {
		if status != nil {
			fmt.Fprintf(status, "Could not trust certificate (%v); continuing with the cert flag instead.\n", err)
		}
		return false
	}
	return caTrustedDarwin()
}

// caTrustedDarwin reports whether the proxy CA carries a user trust setting.
// `security dump-trust-settings` exits non-zero when no settings exist, which
// correctly reads as "not trusted".
func caTrustedDarwin() bool {
	out, err := exec.Command("security", "dump-trust-settings").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), caCommonName)
}

func trustCADarwin(caPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	loginKeychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	cmd := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", loginKeychain, caPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
