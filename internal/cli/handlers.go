package cli

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/kaizakin/osto/internal/auth"
	dbstore "github.com/kaizakin/osto/internal/db"
	"github.com/kaizakin/osto/internal/models"
	"github.com/skip2/go-qrcode"
)

var (
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
)

func promptLine(rl *readline.Instance, prompt string) (string, error) {
	rl.SetPrompt(prompt)
	defer rl.SetPrompt("")
	line, err := rl.Readline()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func promptPassword(rl *readline.Instance, prompt string) (string, error) {
	pass, err := rl.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(pass)), nil
}

// HandleRegister prompts for credentials and registers a new account.
func HandleRegister(rl *readline.Instance, db *sql.DB, state *models.AppState) {
	fmt.Println(bold("\n── Register ──────────────────────────────────"))
	username, err := promptLine(rl, "  Username: ")
	if err != nil || username == "" {
		fmt.Println(red("  ✗ Cancelled or empty username."))
		return
	}
	password, err := promptPassword(rl, "  Password: ")
	if err != nil {
		fmt.Println(red("  ✗ Cancelled."))
		return
	}
	if len(password) < 8 {
		fmt.Println(red("  ✗ Password must be at least 8 characters."))
		return
	}
	confirm, err := promptPassword(rl, "  Confirm password: ")
	if err != nil || password != confirm {
		fmt.Println(red("  ✗ Passwords do not match."))
		return
	}
	if err := auth.RegisterUser(db, username, password); err != nil {
		fmt.Printf("  %s %v\n", red("✗"), err)
		return
	}
	fmt.Printf("  %s Account %s created successfully!\n\n", green("✓"), bold(username))
}

// HandleLogin authenticates a user and creates a session.
func HandleLogin(rl *readline.Instance, db *sql.DB, state *models.AppState) {
	fmt.Println(bold("\n── Login ─────────────────────────────────────"))
	username, err := promptLine(rl, "  Username: ")
	if err != nil {
		fmt.Println(red("  ✗ Cancelled."))
		return
	}
	password, err := promptPassword(rl, "  Password: ")
	if err != nil {
		fmt.Println(red("  ✗ Cancelled."))
		return
	}
	user, err := auth.LoginUser(db, username, password)
	if err != nil {
		fmt.Printf("  %s %v\n\n", red("✗"), err)
		return
	}
	if user.TOTPEnabled {
		code, err := promptLine(rl, "  TOTP code (6 digits): ")
		if err != nil {
			fmt.Println(red("  ✗ Cancelled."))
			return
		}
		if !auth.ValidateTOTPCode(user.TOTPSecret, code) {
			fmt.Println(red("  ✗ Invalid TOTP code."))
			return
		}
	}
	session, err := auth.NewSession(db, user.ID, state.SessionTimeout)
	if err != nil {
		fmt.Printf("  %s Could not create session: %v\n", red("✗"), err)
		return
	}
	state.CurrentUser = user
	state.ActiveSession = session
	fmt.Printf("\n  %s Welcome back, %s!\n", green("✓"), bold(user.Username))
	printUserDetails(user, session)
	fmt.Println()
}

// HandleWhoami displays details about the current user and session.
func HandleWhoami(state *models.AppState) {
	fmt.Println(bold("\n── Who Am I ──────────────────────────────────"))
	printUserDetails(state.CurrentUser, state.ActiveSession)
	fmt.Println()
}

// HandleEnable2FA generates a TOTP secret, shows the QR code, and activates 2FA.
func HandleEnable2FA(rl *readline.Instance, db *sql.DB, state *models.AppState) {
	user := state.CurrentUser
	if user.TOTPEnabled {
		fmt.Println(yellow("  ⚠  2FA is already enabled."))
		return
	}
	fmt.Println(bold("\n── Enable 2FA ────────────────────────────────"))
	key, err := auth.GenerateTOTPSecret(user.Username)
	if err != nil {
		fmt.Printf("  %s Could not generate secret: %v\n", red("✗"), err)
		return
	}
	fmt.Printf("\n  %s\n\n", cyan("Scan this QR code with your authenticator app:"))
	qr, err := qrcode.New(key.URL(), qrcode.Medium)
	if err != nil {
		fmt.Printf("  %s Could not generate QR: %v\n", red("✗"), err)
		return
	}
	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("  %s %s\n\n", bold("Manual key:"), cyan(key.Secret()))
	code, err := promptLine(rl, "  TOTP code: ")
	if err != nil {
		fmt.Println(red("  ✗ Cancelled."))
		return
	}
	if !auth.ValidateTOTPCode(key.Secret(), code) {
		fmt.Println(red("  ✗ Invalid code. 2FA setup aborted."))
		return
	}
	if err := dbstore.SetTOTPSecret(db, user.ID, key.Secret(), true); err != nil {
		fmt.Printf("  %s Could not save 2FA settings: %v\n", red("✗"), err)
		return
	}
	state.CurrentUser.TOTPSecret = key.Secret()
	state.CurrentUser.TOTPEnabled = true
	fmt.Printf("\n  %s Two-factor authentication is now %s!\n\n", green("✓"), green("enabled"))
}

// HandleDisable2FA verifies the current TOTP code then disables 2FA.
func HandleDisable2FA(rl *readline.Instance, db *sql.DB, state *models.AppState) {
	user := state.CurrentUser
	if !user.TOTPEnabled {
		fmt.Println(yellow("  ⚠  2FA is not currently enabled."))
		return
	}
	fmt.Println(bold("\n── Disable 2FA ───────────────────────────────"))
	code, err := promptLine(rl, "  TOTP code: ")
	if err != nil {
		fmt.Println(red("  ✗ Cancelled."))
		return
	}
	if !auth.ValidateTOTPCode(user.TOTPSecret, code) {
		fmt.Println(red("  ✗ Invalid code. 2FA was not disabled."))
		return
	}
	if err := dbstore.SetTOTPSecret(db, user.ID, "", false); err != nil {
		fmt.Printf("  %s Could not update 2FA settings: %v\n", red("✗"), err)
		return
	}
	state.CurrentUser.TOTPSecret = ""
	state.CurrentUser.TOTPEnabled = false
	fmt.Printf("\n  %s Two-factor authentication has been %s.\n\n", green("✓"), yellow("disabled"))
}

// HandleLogout destroys the active session and clears state.
func HandleLogout(db *sql.DB, state *models.AppState) {
	username := state.CurrentUser.Username
	_ = auth.DestroySession(db, state.ActiveSession.ID)
	state.CurrentUser = nil
	state.ActiveSession = nil
	fmt.Printf("  %s Logged out as %s. Goodbye!\n\n", green("✓"), bold(username))
}

// HandleHelp prints context-aware command usage.
func HandleHelp(state *models.AppState) {
	fmt.Println()
	if state.IsLoggedIn() {
		fmt.Println(bold("  Post-login commands:"))
		fmt.Printf("  %-15s %s\n", cyan("whoami"), "Show current user and session info")
		fmt.Printf("  %-15s %s\n", cyan("enable-2fa"), "Set up TOTP two-factor authentication")
		fmt.Printf("  %-15s %s\n", cyan("disable-2fa"), "Remove two-factor authentication")
		fmt.Printf("  %-15s %s\n", cyan("logout"), "End session and return to login prompt")
		fmt.Printf("  %-15s %s\n", cyan("help"), "Show this message")
	} else {
		fmt.Println(bold("  Pre-login commands:"))
		fmt.Printf("  %-15s %s\n", cyan("register"), "Create a new account")
		fmt.Printf("  %-15s %s\n", cyan("login"), "Authenticate with username and password")
		fmt.Printf("  %-15s %s\n", cyan("help"), "Show this message")
		fmt.Printf("  %-15s %s\n", cyan("exit"), "Close the application")
	}
	fmt.Println()
}

func printUserDetails(u *models.User, s *models.Session) {
	mfaStatus := red("Disabled")
	if u.TOTPEnabled {
		mfaStatus = green("Enabled")
	}
	lastLogin := yellow("Never")
	if u.LastLoginAt != nil {
		lastLogin = u.LastLoginAt.Local().Format(time.RFC1123)
	}
	sessionExpiry := "-"
	if s != nil {
		remaining := time.Until(s.ExpiresAt).Round(time.Second)
		sessionExpiry = fmt.Sprintf("%s (in %s)", s.ExpiresAt.Local().Format(time.RFC1123), remaining)
	}
	fmt.Printf("\n  %-20s %s\n", bold("Username:"), cyan(u.Username))
	fmt.Printf("  %-20s %s\n", bold("Registered:"), u.CreatedAt.Local().Format(time.RFC1123))
	fmt.Printf("  %-20s %s\n", bold("Last Login:"), lastLogin)
	fmt.Printf("  %-20s %s\n", bold("MFA Status:"), mfaStatus)
	fmt.Printf("  %-20s %s\n", bold("Session Expires:"), sessionExpiry)
}

// FormatSessionExpiredMsg returns the auto-logout message for an expired session.
func FormatSessionExpiredMsg(username string) string {
	return fmt.Sprintf("\n  %s Session expired for %s. You have been logged out.\n",
		yellow("⚠"), bold(username))
}
