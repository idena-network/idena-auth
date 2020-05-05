package db

import (
	"github.com/idena-network/idena-auth/types"
	"time"
)

type Accessor interface {
	StartSession(version, token, address, nonce string, timestamp time.Time) error
	GetTokenData(version, token string) (TokenData, error)
	Authenticate(version, token, address, nonce string, timestamp time.Time) error
	GetAccount(version, token string) (types.GetAccountResponse, error)
	Logout(version, token string) (types.LogoutResponse, error)
	ClearExpiredSessions(timestamp time.Time) error
}
