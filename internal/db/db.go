package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Open opens or creates a SQLite DB at dbPath, applies the schema, and returns it.
func Open(dbPath, schemaPath string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("db: create data directory: %w", err)
	}
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("db: open %s: %w", dbPath, err)
	}
	if err := database.Ping(); err != nil {
		database.Close()
		return nil, fmt.Errorf("db: ping %s: %w", dbPath, err)
	}
	for _, p := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
	} {
		if _, err := database.Exec(p); err != nil {
			database.Close()
			return nil, fmt.Errorf("db: pragma %q: %w", p, err)
		}
	}
	if err := applySchema(database, schemaPath); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

func applySchema(database *sql.DB, schemaPath string) error {
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("db: read schema %s: %w", schemaPath, err)
	}
	if _, err := database.Exec(string(schema)); err != nil {
		return fmt.Errorf("db: apply schema: %w", err)
	}
	return nil
}
