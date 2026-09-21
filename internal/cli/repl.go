package cli

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"
	"github.com/kaizakin/osto/internal/auth"
	"github.com/kaizakin/osto/internal/models"
)

const (
	promptUnauthenticated = "osto> "
	historyFile           = "/tmp/osto-history"
)

func promptAuthenticated(username string) string {
	return fmt.Sprintf("osto (%s)> ", username)
}

// Run starts the interactive REPL and blocks until the user exits.
func Run(db *sql.DB, state *models.AppState) error {
	completer := &DynamicCompleter{State: state}
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          promptUnauthenticated,
		HistoryFile:     historyFile,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("repl: create readline: %w", err)
	}
	defer rl.Close()

	printBanner()

	for {
		if state.IsLoggedIn() {
			rl.SetPrompt(promptAuthenticated(state.CurrentUser.Username))
		} else {
			rl.SetPrompt(promptUnauthenticated)
		}

		line, err := rl.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			fmt.Println()
			continue
		}
		if errors.Is(err, io.EOF) {
			fmt.Println(green("\n  Goodbye!"))
			return nil
		}
		if err != nil {
			return fmt.Errorf("repl: readline: %w", err)
		}

		cmd := strings.TrimSpace(strings.ToLower(line))
		if cmd == "" {
			continue
		}

		if state.IsLoggedIn() {
			valid, valErr := auth.ValidateSession(db, state.ActiveSession.ID)
			if valErr != nil {
				fmt.Printf("  %s Session validation error: %v\n", red("✗"), valErr)
			}
			if valid == nil {
				username := state.CurrentUser.Username
				state.CurrentUser = nil
				state.ActiveSession = nil
				fmt.Print(FormatSessionExpiredMsg(username))
				continue
			}
		}

		if state.IsLoggedIn() {
			dispatchPostLogin(cmd, rl, db, state)
		} else {
			if stop := dispatchPreLogin(cmd, rl, db, state); stop {
				return nil
			}
		}
	}
}

func dispatchPreLogin(cmd string, rl *readline.Instance, db *sql.DB, state *models.AppState) bool {
	switch cmd {
	case "register":
		HandleRegister(rl, db, state)
	case "login":
		HandleLogin(rl, db, state)
	case "help":
		HandleHelp(state)
	case "exit", "quit":
		fmt.Println(green("\n  Goodbye!"))
		return true
	default:
		fmt.Printf("  %s Unknown command %q. Type %s for help.\n\n", yellow("⚠"), cmd, cyan("help"))
	}
	return false
}

func dispatchPostLogin(cmd string, rl *readline.Instance, db *sql.DB, state *models.AppState) {
	switch cmd {
	case "whoami":
		HandleWhoami(state)
	case "enable-2fa":
		HandleEnable2FA(rl, db, state)
	case "disable-2fa":
		HandleDisable2FA(rl, db, state)
	case "logout":
		HandleLogout(db, state)
	case "help":
		HandleHelp(state)
	case "exit", "quit":
		HandleLogout(db, state)
		fmt.Println(green("  Goodbye!"))
	default:
		fmt.Printf("  %s Unknown command %q. Type %s for help.\n\n", yellow("⚠"), cmd, cyan("help"))
	}
}

func printBanner() {
	fmt.Println()
	fmt.Println(bold("  ╔══════════════════════════════════════╗"))
	fmt.Println(bold("  ║             osto  v1.0.0             ║"))
	fmt.Println(bold("  ║  Secure CLI Login with TOTP 2FA      ║"))
	fmt.Println(bold("  ╚══════════════════════════════════════╝"))
	fmt.Printf("\n  Type %s to get started.\n\n", cyan("help"))
}
