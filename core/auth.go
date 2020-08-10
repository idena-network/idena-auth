package core

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/idena-network/idena-auth/db"
	"github.com/idena-network/idena-auth/types"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/hexutil"
	"github.com/idena-network/idena-go/crypto"
	log "github.com/inconshreveable/log15"
	"time"
)

type Auth interface {
	StartSession(version string, request types.StartSessionRequest) (types.StartSessionResponse, error)
	Authenticate(version string, request types.AuthenticateRequest) (types.AuthenticateResponse, error)
	GetAccount(version, token string) (types.GetAccountResponse, error)
	Logout(version string, request types.LogoutRequest) (types.LogoutResponse, error)
}

func NewAuth(db db.Accessor, lifeTime, clearExpiredSessionsInterval time.Duration) Auth {
	a := &authImpl{
		db:                           db,
		lifeTime:                     lifeTime,
		clearExpiredSessionsInterval: clearExpiredSessionsInterval,
	}
	go a.loopClearExpiredSessions()
	return a
}

type authImpl struct {
	db                           db.Accessor
	lifeTime                     time.Duration
	clearExpiredSessionsInterval time.Duration
}

func (a *authImpl) loopClearExpiredSessions() {
	for {
		timestamp := time.Now().Add(-a.lifeTime)
		if err := a.db.ClearExpiredSessions(timestamp); err != nil {
			log.Error(fmt.Sprintf("Unable to clear expired sessions: %v", err))
		} else {
			log.Debug("Expired sessions cleared")
		}
		time.Sleep(a.clearExpiredSessionsInterval)
	}
}

func checkVersion(version string) error {
	if version != "v1" {
		return errors.New(fmt.Sprintf("unsupported version"))
	}
	return nil
}

func (a *authImpl) StartSession(version string, request types.StartSessionRequest) (types.StartSessionResponse, error) {
	if err := checkVersion(version); err != nil {
		return types.StartSessionResponse{}, err
	}
	timestamp := time.Now()
	nonce := generateNonce()
	if err := a.db.StartSession(version, request.Token, request.Address, nonce, timestamp); err != nil {
		return types.StartSessionResponse{}, err
	}
	return types.StartSessionResponse{
		Nonce: nonce,
	}, nil
}

func generateNonce() string {
	return fmt.Sprintf("signin-%v", uuid.New().String())
}

func (a *authImpl) Authenticate(version string, request types.AuthenticateRequest) (types.AuthenticateResponse, error) {
	if err := checkVersion(version); err != nil {
		return types.AuthenticateResponse{}, err
	}
	timestamp := time.Now()
	tokenData, err := a.db.GetTokenData(version, request.Token)
	if err != nil {
		return types.AuthenticateResponse{}, err
	}
	if tokenData.Authenticated {
		return types.AuthenticateResponse{}, errors.New("already authenticated")
	}
	if timestamp.Sub(tokenData.Timestamp) > a.lifeTime {
		return types.AuthenticateResponse{}, types.NoDataFound
	}
	address, err := signatureAddress(tokenData.Nonce, request.Signature)
	if err != nil {
		return types.AuthenticateResponse{}, err
	}
	if address != common.HexToAddress(tokenData.Address) {
		return types.AuthenticateResponse{
			Authenticated: false,
		}, nil
	}
	if err := a.db.Authenticate(version, request.Token, tokenData.Address, tokenData.Nonce, timestamp); err != nil {
		return types.AuthenticateResponse{}, err
	}
	return types.AuthenticateResponse{
		Authenticated: true,
	}, nil
}

func signatureAddress(nonce, signature string) (common.Address, error) {
	hash := signatureHash(nonce)
	signatureBytes, err := hexutil.Decode(signature)
	if err != nil {
		return common.Address{}, nil
	}
	pubKey, err := crypto.Ecrecover(hash[:], signatureBytes)
	if err != nil {
		return common.Address{}, err
	}
	addr, err := crypto.PubKeyBytesToAddress(pubKey)
	if err != nil {
		return common.Address{}, err
	}
	return addr, nil
}

func signatureHash(value string) common.Hash {
	h := crypto.Hash([]byte(value))
	return crypto.Hash(h[:])
}

func (a *authImpl) GetAccount(version, token string) (types.GetAccountResponse, error) {
	if err := checkVersion(version); err != nil {
		return types.GetAccountResponse{}, err
	}
	return a.db.GetAccount(version, token)
}

func (a *authImpl) Logout(version string, request types.LogoutRequest) (types.LogoutResponse, error) {
	if err := checkVersion(version); err != nil {
		return types.LogoutResponse{}, err
	}
	return a.db.Logout(version, request.Token)
}
