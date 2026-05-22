package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/core/logger"
)

func LoadConfig(configPath string) (*config.Config, error) {
	// 1) if -c flag is set -> must read config from file
	// 2) if $PGRWL_CONFIG_PATH is set -> must read config from file
	// 3) read config with go-envconfig otherwise
	var cfg *config.Config
	var err error
	if configPath != "" {
		cfg, err = config.FromFile(configPath)
		if err != nil {
			return nil, err
		}
	} else {
		cfg, err = config.FromEnvs()
		if err != nil {
			return nil, err
		}
	}

	// debug config (NOTE: sensitive fields are hidden)
	_, _ = fmt.Fprintf(os.Stderr, "STARTING WITH CONFIGURATION (%s):\n%s\n\n",
		filepath.ToSlash(configPath),
		cfg.String(),
	)

	logger.Init(&logger.Opts{
		Level:     cfg.Log.Level,
		Format:    cfg.Log.Format,
		AddSource: cfg.Log.AddSource,
	})
	return cfg, nil
}

func CheckPgEnvsAreSet() error {
	var emptyEnvs []string

	pgPassFile := os.Getenv("PGPASSFILE")

	for _, name := range []string{"PGHOST", "PGPORT", "PGUSER"} {
		if os.Getenv(name) == "" {
			emptyEnvs = append(emptyEnvs, name)
		}
	}

	if os.Getenv("PGPASSWORD") == "" && pgPassFile == "" {
		emptyEnvs = append(emptyEnvs, "PGPASSWORD or PGPASSFILE")
	}

	if len(emptyEnvs) > 0 {
		return fmt.Errorf("[FATAL] receive: required env vars are empty: [%s]", strings.Join(emptyEnvs, " "))
	}

	if pgPassFile != "" {
		if _, err := os.Stat(filepath.Clean(pgPassFile)); os.IsNotExist(err) {
			return fmt.Errorf("[FATAL] PGPASSFILE does not exist: %s", pgPassFile)
		}
	}

	return nil
}
