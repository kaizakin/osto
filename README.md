# auth-cli

A **secure, containerized, interactive CLI Login System** written in Go.

Features:
- 🔐 **TOTP-based 2FA** — Google Authenticator compatible (RFC 6238)  
- 🗄️  **SQLite persistence** — pure-Go driver, no CGO, no C compiler needed  
- 🔒 **Session management** — configurable timeout with automatic expiry logout  
- 🚫 **Account lockout** — 15-minute lock after 3 consecutive failed logins  
- 💻 **Interactive REPL** — readline with tab-completion and command history  
- 🐳 **Docker-ready** — multi-stage build, TTY-compatible Compose config  

---

## System Prerequisites

### Running with Docker (recommended)
| Tool | Minimum version |
|------|----------------|
| Docker | 20.10+ |
| Docker Compose | v2+ (`docker compose` not `docker-compose`) |

### Local development
| Tool | Minimum version |
|------|----------------|
| Go | 1.23+ |
| No C compiler needed | (pure-Go SQLite driver) |

---

## Quickstart

### Docker (one command)

```bash
git clone https://github.com/kaizakin/osto auth-cli
cd auth-cli
docker compose up --build
```

This will:
1. Build the Go binary inside an Alpine builder container (no local Go needed)
2. Create a minimal Alpine runtime image (~18 MB)
3. Mount a named Docker volume `sqlite_data` at `/app/data` for DB persistence
4. Drop you into the interactive REPL

### Stopping and restarting (data persists)

```bash
# Stop (volume is preserved)
docker compose down

# Restart — your registered users are still there
docker compose up
```

---

## Interactive Attach

The `docker compose up` command attaches your terminal directly. If you run in
detached mode or need to re-attach:

```bash
# Run interactively from scratch (preferred for fresh sessions):
docker compose run --rm app

# Attach to an already-running container:
docker attach $(docker compose ps -q app)
# Press Enter if the prompt does not appear immediately.
# Detach without stopping: Ctrl-P Ctrl-Q
```

---

## Local Development

```bash
# Install dependencies
go mod download

# Run directly (schema.sql must be at ./db/schema.sql — repo root)
go run ./cmd/app

# Build binary
go build -o auth-cli ./cmd/app

# Run tests
go test ./... -v -count=1
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/app/data/auth.db` (Docker) / `./data/auth.db` (local) | Path to the SQLite database file |
| `SCHEMA_PATH` | auto-detected | Path to `db/schema.sql` |
| `SESSION_TIMEOUT` | `15m` | Session duration (any Go duration string: `30m`, `1h`, `90s`) |

---

## Usage

### Pre-login prompt: `auth-cli> `

| Command | Description |
|---------|-------------|
| `register` | Create a new account (prompts username, password, confirm) |
| `login` | Authenticate (prompts username + password; TOTP if enabled) |
| `help` | Show available commands |
| `exit` | Close the application |

### Post-login prompt: `auth-cli (username)> `

| Command | Description |
|---------|-------------|
| `whoami` | Display username, MFA status, session expiry, last login |
| `enable-2fa` | Generate TOTP secret, display QR code, verify and activate |
| `disable-2fa` | Verify current TOTP code and deactivate 2FA |
| `logout` | Destroy session and return to login prompt |
| `help` | Show available commands |

### Tab completion

Press `Tab` at any time to see and cycle through available commands for the
current state (pre/post-login).

---

## Project Structure

```
.
├── cmd/
│   └── app/
│       └── main.go           # Entry point: DB init, env config, REPL start
├── internal/
│   ├── auth/
│   │   ├── auth.go           # Bcrypt, TOTP generation/validation, session token
│   │   ├── service.go        # RegisterUser, LoginUser, lockout, session lifecycle
│   │   └── auth_test.go      # 14 unit tests (bcrypt, lockout, session, TOTP)
│   ├── cli/
│   │   ├── completer.go      # Dynamic readline tab completer
│   │   ├── handlers.go       # One handler per command with color output
│   │   └── repl.go           # Readline REPL loop, prompt updates, dispatch
│   ├── db/
│   │   ├── db.go             # SQLite Open(), schema application, WAL+FK pragmas
│   │   └── store.go          # DAL: user and session CRUD
│   └── models/
│       └── models.go         # User, Session, AppState structs
├── db/
│   └── schema.sql            # CREATE TABLE IF NOT EXISTS for users + sessions
├── Dockerfile                # Multi-stage: Go 1.23 Alpine builder → Alpine runtime
├── docker-compose.yml        # stdin_open + tty, named volume for persistence
├── .dockerignore
├── go.mod
└── README.md
```

---

## Security Design Decisions

### Password Hashing — bcrypt cost 12
bcrypt is used with a work factor of 12 (~250 ms per hash on a modern CPU).
This cost is high enough to make offline dictionary attacks impractical while
remaining imperceptible to a human typing interactively.

### Account Lockout
After **3 consecutive failed login attempts**, the account is locked for
**15 minutes** (`locked_until` in the DB). The lockout check happens *before*
bcrypt comparison so that even the correct password is rejected during the
window. This mitigates both online brute-force and credential-stuffing attacks.

### Session Token Entropy
Session IDs are **32-byte random values from `crypto/rand`**, encoded as a
64-character lowercase hex string. This provides 256 bits of entropy —
sufficient to make guessing a valid token computationally infeasible.

### Session Expiry
Sessions expire after a configurable duration (default: 15 minutes). The REPL
checks session validity **on every command iteration** — not just at login — so
a session that expires mid-use is detected immediately and the user is logged
out gracefully without needing a separate background goroutine.

### TOTP (RFC 6238)
TOTP secrets are generated using SHA-1 with a 30-second period and 6-digit
codes — the parameters required by Google Authenticator and most RFC 6238
clients. A ±1 period tolerance window is used to account for clock skew.

The TOTP secret is only persisted (`totp_enabled = 1`) **after** the user
provides a valid code, preventing a half-configured 2FA state.

### No CGO
The project uses `modernc.org/sqlite`, a pure-Go port of SQLite. This means:
- No C compiler is needed for builds or Docker images
- Cross-compilation is straightforward
- The Alpine runtime image needs no `musl-dev` or `gcc`

### Non-root Docker user
The runtime container runs as a dedicated non-root `appuser` for defence in
depth. The `/app/data` directory is pre-chowned to this user.

---

## Running Tests

```bash
go test ./... -v -count=1
```

Expected output: **14 tests, all PASS** across the `internal/auth` package.

```
=== RUN   TestHashPassword                --- PASS
=== RUN   TestCheckPasswordCorrect        --- PASS
=== RUN   TestCheckPasswordIncorrect      --- PASS
=== RUN   TestHashesAreDifferent          --- PASS
=== RUN   TestLoginLockoutAfterThreeFailures --- PASS
=== RUN   TestSuccessfulLoginResetsFailedAttempts --- PASS
=== RUN   TestLockedAccountRejectsCorrectPassword --- PASS
=== RUN   TestNewSessionIsValid           --- PASS
=== RUN   TestValidateSessionExpired      --- PASS
=== RUN   TestDestroySession              --- PASS
=== RUN   TestGenerateTOTPSecret          --- PASS
=== RUN   TestValidateTOTPCodeSuccess     --- PASS
=== RUN   TestValidateTOTPCodeInvalid     --- PASS
=== RUN   TestGenerateSessionIDUniqueness --- PASS
ok  github.com/kaizakin/osto/internal/auth
```
