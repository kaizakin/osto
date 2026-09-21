package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kaizakin/osto/internal/cli"
	dbpkg "github.com/kaizakin/osto/internal/db"
	"github.com/kaizakin/osto/internal/models"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		if isRunningInDocker() {
			dbPath = "/app/data/auth.db"
		} else {
			dbPath = filepath.Join("data", "auth.db")
		}
	}

	schemaPath := os.Getenv("SCHEMA_PATH")
	if schemaPath == "" {
		schemaPath = resolveSchemaPath()
	}

	sessionTimeout := 15 * time.Minute
	if raw := os.Getenv("SESSION_TIMEOUT"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			sessionTimeout = d
		} else {
			log.Printf("warning: invalid SESSION_TIMEOUT %q, using 15m", raw)
		}
	}

	database, err := dbpkg.Open(dbPath, schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: could not open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := dbpkg.DeleteExpiredSessions(database); err != nil {
		log.Printf("warning: could not purge expired sessions: %v", err)
	}

	state := &models.AppState{SessionTimeout: sessionTimeout}

	if err := cli.Run(database, state); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: REPL error: %v\n", err)
		os.Exit(1)
	}
}

func isRunningInDocker() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func resolveSchemaPath() string {
	if exePath, err := os.Executable(); err == nil {
		if c := filepath.Join(filepath.Dir(exePath), "db", "schema.sql"); fileExists(c) {
			return c
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if c := filepath.Join(wd, "db", "schema.sql"); fileExists(c) {
			return c
		}
	}
	if fileExists("/app/db/schema.sql") {
		return "/app/db/schema.sql"
	}
	return filepath.Join("db", "schema.sql")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
