package main

import (
	"github.com/idena-network/idena-auth/config"
	"github.com/idena-network/idena-auth/core"
	"github.com/idena-network/idena-auth/db"
	"github.com/idena-network/idena-auth/db/postgres"
	"github.com/idena-network/idena-auth/server"
	log "github.com/inconshreveable/log15"
	"os"
	"runtime"
	"time"
)

func initLogger(verbosity int) {
	var handler log.Handler
	logLvl := log.Lvl(verbosity)
	if runtime.GOOS == "windows" {
		handler = log.LvlFilterHandler(logLvl, log.StreamHandler(os.Stdout, log.LogfmtFormat()))
	} else {
		handler = log.LvlFilterHandler(logLvl, log.StreamHandler(os.Stderr, log.TerminalFormat()))
	}
	log.Root().SetHandler(handler)
}

func startServer(appConfig *config.Config) {
	initLogger(appConfig.Verbosity)
	server.NewServer(appConfig.Server.Port, initAuth(appConfig)).Start()
}

func initAuth(appConfig *config.Config) core.Auth {
	return core.NewAuth(initDbAccessor(appConfig), time.Second*time.Duration(appConfig.TokenLifeTimeSec), time.Minute*5)
}

func initDbAccessor(appConfig *config.Config) db.Accessor {
	return postgres.NewAccessor(appConfig.Postgres.ConnStr, appConfig.Postgres.ScriptsDir)
}
