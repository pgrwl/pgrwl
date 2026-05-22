package receiveapi

import (
	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/core/xlog"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
)

type Opts struct {
	PGRW         xlog.PgReceiveWal
	BaseDir      string
	Storage      *st.VariadicStorage
	Cfg          *config.Config
	StopReceiver func()
}
