package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backup"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/restore"
	"github.com/pgrwl/pgrwl/internal/opt/cmd"
	"github.com/pgrwl/pgrwl/internal/opt/shared/x/strx"
	"github.com/pgrwl/pgrwl/internal/version"
	cliv3 "github.com/urfave/cli/v3"
)

func main() {
	application := newCliApp()
	if err := application.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func newCliApp() *cliv3.Command {
	cliv3.VersionPrinter = func(cmd *cliv3.Command) {
		_, _ = fmt.Fprintf(cmd.Root().Writer, "%s", cmd.Root().Version)
	}
	return &cliv3.Command{
		Name:    "pgrwl",
		Usage:   "Cloud-native continuous backup for PostgreSQL",
		Version: version.Version,
		Commands: []*cliv3.Command{
			daemonCmd(),
			backupCreateCmd(),
			backupRestoreCmd(),
			restoreCommandCmd(),
			validateCmd(),
		},
	}
}

// commands

const (
	configKey = "config"
)

var (
	configFlag = &cliv3.StringFlag{
		Name:    configKey,
		Usage:   "Path to config file",
		Aliases: []string{"c"},
		Sources: cliv3.EnvVars("PGRWL_CONFIG_PATH"),
	}
)

func daemonCmd() *cliv3.Command {
	return &cliv3.Command{
		Name:  "daemon",
		Usage: "Running in a daemon mode",
		Flags: []cliv3.Flag{
			configFlag,
		},
		Action: func(_ context.Context, c *cliv3.Command) error {
			var err error

			cfg, err := cmd.LoadConfig(c.String(configKey))
			if err != nil {
				return err
			}

			err = cmd.CheckPgEnvsAreSet()
			if err != nil {
				return err
			}

			return cmd.RunReceiveMode(&cmd.ReceiveModeOpts{
				ReceiveDirectory: filepath.ToSlash(cfg.Main.Directory),
				ListenPort:       cfg.Main.ListenPort,
				Slot:             cfg.Receiver.Slot,
				NoLoop:           cfg.Receiver.NoLoop,
			})
		},
	}
}

func backupCreateCmd() *cliv3.Command {
	return &cliv3.Command{
		Name:  "backup",
		Usage: "Create basebackup using streaming replication protocol",
		Flags: []cliv3.Flag{
			configFlag,
		},
		Action: func(_ context.Context, c *cliv3.Command) error {
			var err error

			err = cmd.CheckPgEnvsAreSet()
			if err != nil {
				return err
			}

			cfg, err := cmd.LoadConfig(c.String(configKey))
			if err != nil {
				return err
			}

			_, err = backup.CreateBaseBackup(context.Background(),
				&backup.CreateBaseBackupOpts{
					Directory: cfg.Main.Directory,
				},
			)
			return err
		},
	}
}

func backupRestoreCmd() *cliv3.Command {
	return &cliv3.Command{
		Name:  "restore",
		Usage: "Retrieve basebackup",
		Flags: []cliv3.Flag{
			configFlag,
			&cliv3.StringFlag{
				Name:  "id",
				Usage: "Backup id to restore (20060102150405), the 'latest' will be used if not set",
			},
			&cliv3.StringFlag{
				Name:     "dest",
				Usage:    "Restore to destination",
				Required: true,
			},
		},
		Action: func(_ context.Context, c *cliv3.Command) error {
			cfg, err := cmd.LoadConfig(c.String(configKey))
			if err != nil {
				return err
			}
			return restore.RestoreBaseBackup(context.Background(), cfg,
				c.String("id"),
				c.String("dest"),
			)
		},
	}
}

func restoreCommandCmd() *cliv3.Command {
	return &cliv3.Command{
		Name:  "restore-command",
		Usage: "Fetch a single WAL file by name",

		Description: strx.HeredocTrim(`
				Implements PostgreSQL restore_command.

				Example usage in postgresql.conf:
				restore_command = 'pgrwl restore-command --addr=k8s-worker5:30266 %f %p'
				`),

		Flags: []cliv3.Flag{
			&cliv3.StringFlag{
				Name:     "addr",
				Required: true,
				Usage:    "The address of pgrwl running in a serve mode",
			},
		},
		Action: func(_ context.Context, c *cliv3.Command) error {
			args := c.Args()
			if args.Len() != 2 {
				return fmt.Errorf("usage: restore-command <WAL_FILE_NAME> <DEST_PATH>")
			}

			walFile := args.Get(0)
			destPath := args.Get(1)

			return cmd.ExecRestoreCommand(
				walFile,
				destPath,
				&cmd.RestoreCommandOpts{
					Addr: c.String("addr"),
				},
			)
		},
	}
}

func validateCmd() *cliv3.Command {
	return &cliv3.Command{
		Name:  "validate",
		Usage: "Validate the config file without running the application",
		Flags: []cliv3.Flag{
			configFlag,
		},
		Action: func(_ context.Context, c *cliv3.Command) error {
			configPath := c.String(configKey)
			_, err := cmd.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("configuration error: %v\n", err)
				return err
			}
			return nil
		},
	}
}
