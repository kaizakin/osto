# osto

Interactive login CLI in Go. Register, log in, optional TOTP, then a few account commands. State lives in SQLite. The prompt is readline: tab completion and up-arrow history.

This is a local demo, not a network auth server.

## Run

Docker, from the repo root:

```bash
docker compose up --build
```

Stay attached. `help` is a prompt command, not something you `docker exec`. Detach with Ctrl-P Ctrl-Q. Users survive `docker compose down` because they sit on the `sqlite_data` volume. `down -v` deletes that volume.

Without Docker, Go 1.23+:

```bash
make
./osto
make test
```

`make sqlc` regenerates query code from `db/schema.sql` and `db/queries/`. Do not edit `internal/db/sqlcgen` by hand.

Env vars, all optional:

- `DB_PATH` defaults to `/app/data/auth.db` in Docker and `./data/auth.db` locally
- `SCHEMA_PATH` is found next to the binary, then `./db/schema.sql`, then `/app/db/schema.sql`
- `SESSION_TIMEOUT` is a Go duration. Default `15m`

## Prompt

Before login: `register`, `login`, `help`, `exit`.

After login: `whoami`, `enable-2fa`, `disable-2fa`, `logout`, `help`.

Register asks again if the password is under 8 characters. Login asks again on a wrong password. Ctrl-C leaves the password prompt.

## Authentication

Passwords are bcrypt at cost 12. Each hash gets its own salt. The CLI never keeps the secret as a Go `string`. It reads `[]byte` from the terminal and overwrites that buffer after hash or compare.

Three failed logins in a row lock the account for 15 minutes. The lock is checked before bcrypt, so the correct password is rejected for the whole window. A successful login resets the counter.

Sessions are a 32-byte value from `crypto/rand`. The process holds the raw hex token. The `sessions` table stores `SHA-256` of those 32 bytes. Each command hashes the in-memory token and looks up the digest. Logout and expiry delete by digest. A leaked database does not contain a usable session id.

Sessions last `SESSION_TIMEOUT`. The REPL checks expiry on every command. There is no sliding refresh and no restore after restart.

TOTP is RFC 6238, SHA-1, 6 digits, 30 seconds, issuer `osto`. `enable-2fa` prints a QR and a manual key. The secret is written only after a valid code. `disable-2fa` needs a live code. Login asks for TOTP after the password if 2FA is on.

## Container hardening

The runtime image is Alpine. The process is uid/gid 1000, `appuser`. The binary is built with `CGO_ENABLED=0` against `modernc.org/sqlite`, so the image has no gcc. The build uses `-mod=vendor`.

Compose sets:

- `read_only: true` on the root filesystem
- `cap_drop: ALL`
- `no-new-privileges: true`
- `sqlite_data` mounted read-write at `/app/data`
- `/tmp` as tmpfs with `noexec` and `nosuid`, because history is `/tmp/osto-history`

Docker creates named volumes as root. The app cannot `chown` them. `data-init` runs first as root with only `CHOWN`, sets `/app/data` to 1000:1000, and exits. Same volume, two mounts.

SQLite uses WAL, foreign keys, and a 5s busy timeout.
