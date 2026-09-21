-- name: CreateUser :one
INSERT INTO users (username, password_hash)
VALUES (sqlc.arg(username), sqlc.arg(password_hash))
RETURNING id;

-- name: GetUserByUsername :one
SELECT id,
       username,
       password_hash,
       totp_secret,
       totp_enabled,
       failed_attempts,
       locked_until,
       created_at,
       last_login_at
FROM users
WHERE username = sqlc.arg(username)
LIMIT 1;

-- name: UpdateFailedAttempts :exec
UPDATE users
SET failed_attempts = sqlc.arg(failed_attempts),
    locked_until = sqlc.narg(locked_until)
WHERE id = sqlc.arg(id);

-- name: ResetFailedAttempts :exec
UPDATE users
SET failed_attempts = 0,
    locked_until = NULL
WHERE id = sqlc.arg(id);

-- name: UpdateLastLogin :exec
UPDATE users
SET last_login_at = sqlc.arg(last_login_at)
WHERE id = sqlc.arg(id);

-- name: SetTOTPSecret :exec
UPDATE users
SET totp_secret = sqlc.arg(totp_secret),
    totp_enabled = sqlc.arg(totp_enabled)
WHERE id = sqlc.arg(id);
