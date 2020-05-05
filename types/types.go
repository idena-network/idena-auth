package types

import "github.com/pkg/errors"

type StartSessionRequest struct {
	Token   string `json:"token"`
	Address string `json:"address"`
}

type StartSessionResponse struct {
	Nonce string `json:"nonce"`
}

type AuthenticateRequest struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

type AuthenticateResponse struct {
	Authenticated bool `json:"authenticated"`
}

type GetAccountResponse struct {
	Address string `json:"address"`
}

type LogoutRequest struct {
	Token string `json:"token"`
}

type LogoutResponse struct {
	Loggedout bool `json:"loggedout"`
}

type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

var NoDataFound = errors.New("no data found")
