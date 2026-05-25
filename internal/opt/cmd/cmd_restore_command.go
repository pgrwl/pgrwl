package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/pgrwl/pgrwl/internal/opt/shared/x/cmdx"
)

type RestoreCommandOpts struct {
	Addr string
}

func ExecRestoreCommand(walFileName, walFilePath string, opts *RestoreCommandOpts) error {
	slog.Debug("wal-restore",
		slog.String("f", walFileName),
		slog.String("p", walFilePath),
	)

	addr, err := cmdx.Addr(opts.Addr)
	if err != nil {
		return err
	}
	baseURL := fmt.Sprintf("%s/api/v1/wal/%s", addr, walFileName)

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error: %s", resp.Status)
	}

	// Save to file
	fileDst, err := os.OpenFile(walFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o666)
	if err != nil {
		return err
	}

	if _, err = io.Copy(fileDst, resp.Body); err != nil {
		_ = fileDst.Close()
		_ = os.Remove(walFilePath)
		return err
	}

	return fileDst.Close()
}
