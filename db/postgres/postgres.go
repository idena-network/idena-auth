package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/idena-network/idena-auth/db"
	"github.com/idena-network/idena-auth/types"
	log "github.com/inconshreveable/log15"
	_ "github.com/lib/pq"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"
)

const (
	initQuery                 = "init.sql"
	startSessionQuery         = "startSession.sql"
	getTokenDataQuery         = "getTokenData.sql"
	authenticateQuery         = "authenticate.sql"
	getAccountQuery           = "getAccount.sql"
	logoutQuery               = "logout.sql"
	clearExpiredSessionsQuery = "clearExpiredSessions.sql"
)

type accessor struct {
	db      *sql.DB
	queries map[string]string
}

func NewAccessor(connStr string, scriptsDirPath string) db.Accessor {
	sqlDb, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	a := &accessor{
		db:      sqlDb,
		queries: readQueries(scriptsDirPath),
	}
	for {
		if err := a.init(); err != nil {
			log.Error(fmt.Sprintf("Unable to initialize postgres connection: %v", err))
			time.Sleep(time.Second * 10)
			continue
		}
		break
	}
	return a
}

func readQueries(scriptsDirPath string) map[string]string {
	files, err := ioutil.ReadDir(scriptsDirPath)
	if err != nil {
		panic(err)
	}
	queries := make(map[string]string)
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		bytes, err := ioutil.ReadFile(filepath.Join(scriptsDirPath, file.Name()))
		if err != nil {
			panic(err)
		}
		queryName := file.Name()
		query := string(bytes)
		queries[queryName] = query
		log.Debug(fmt.Sprintf("Read query %s from %s", queryName, scriptsDirPath))
	}
	return queries
}

func (a *accessor) init() error {
	if err := a.db.Ping(); err != nil {
		return err
	}
	if _, err := a.db.Exec(a.getQuery(initQuery)); err != nil {
		return err
	}
	return nil
}

func (a *accessor) getQuery(name string) string {
	if query, present := a.queries[name]; present {
		return query
	}
	panic(fmt.Sprintf("There is no query '%s'", name))
}

func (a *accessor) StartSession(version, token, address, nonce string, timestamp time.Time) error {
	var errorMsg sql.NullString
	if err := a.db.QueryRow(a.getQuery(startSessionQuery),
		version, token, address, nonce, timestamp).Scan(&errorMsg); err != nil {
		return err
	}
	if errorMsg.Valid {
		return errors.New(errorMsg.String)
	}
	return nil
}

func (a *accessor) GetTokenData(version, token string) (db.TokenData, error) {
	var res db.TokenData
	err := a.db.QueryRow(a.getQuery(getTokenDataQuery), token).Scan(
		&res.Address,
		&res.Nonce,
		&res.Authenticated,
		&res.Timestamp,
	)
	if err == sql.ErrNoRows {
		err = types.NoDataFound
	}
	return res, err
}

func (a *accessor) Authenticate(version, token, address, nonce string, timestamp time.Time) error {
	var errorMsg sql.NullString
	if err := a.db.QueryRow(a.getQuery(authenticateQuery),
		version, token, address, nonce, timestamp).Scan(&errorMsg); err != nil {
		return err
	}
	if errorMsg.Valid {
		return errors.New(errorMsg.String)
	}
	return nil
}

func (a *accessor) GetAccount(version, token string) (types.GetAccountResponse, error) {
	var res types.GetAccountResponse
	err := a.db.QueryRow(a.getQuery(getAccountQuery), token).Scan(&res.Address)
	if err == sql.ErrNoRows {
		err = types.NoDataFound
	}
	return res, err
}

func (a *accessor) Logout(version, token string) (types.LogoutResponse, error) {
	var res bool
	if err := a.db.QueryRow(a.getQuery(logoutQuery), version, token).Scan(&res); err != nil {
		return types.LogoutResponse{}, err
	}
	return types.LogoutResponse{
		Loggedout: res,
	}, nil
}

func (a *accessor) ClearExpiredSessions(timestamp time.Time) error {
	_, err := a.db.Exec(a.getQuery(clearExpiredSessionsQuery), timestamp)
	return err
}
