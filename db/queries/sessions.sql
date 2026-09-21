-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(expires_at));

-- name: GetSession :one
SELECT id, user_id, expires_at, created_at
FROM sessions
WHERE id = sqlc.arg(id)
LIMIT 1;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = sqlc.arg(id);

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions
WHERE expires_at <= sqlc.arg(expires_at);
