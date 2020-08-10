package server

import (
	"bytes"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/idena-network/idena-auth/core"
	"github.com/idena-network/idena-auth/db/postgres"
	"github.com/idena-network/idena-auth/types"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/hexutil"
	"github.com/idena-network/idena-go/crypto"
	"github.com/idena-network/idena-go/tests"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

const (
	port    = 10080
	connStr = "postgres://postgres@localhost?sslmode=disable"
	schema  = "auth_auto_test"
)

func Test_StartSession(t *testing.T) {
	s := startTestServer()
	defer s.Stop()

	address := tests.GetRandAddr()

	// When
	response, err := sendStartSessionRequest("bad_version", types.StartSessionRequest{
		Token:   "token1",
		Address: address.Hex(),
	})
	// Then
	require.Nil(t, err)
	require.False(t, response.Success)
	require.Equal(t, "unsupported version", response.Error)

	// When
	response, err = sendStartSessionRequest("v1", types.StartSessionRequest{
		Token:   "token1",
		Address: address.Hex(),
	})
	// Then
	require.Nil(t, err)
	require.True(t, response.Success)
	require.True(t, len(response.Data.(*types.StartSessionResponse).Nonce) > 0)

	// When
	response, err = sendStartSessionRequest("v1", types.StartSessionRequest{
		Token:   "token1",
		Address: address.Hex(),
	})
	// Then
	require.Nil(t, err)
	require.False(t, response.Success)
	require.Equal(t, "duplicate token", response.Error)
}

func Test_Authenticate(t *testing.T) {
	s := startTestServer()
	defer s.Stop()

	key, _ := crypto.GenerateKey()
	address := crypto.PubkeyToAddress(key.PublicKey)
	startSessionResponse, _ := sendStartSessionRequest("v1", types.StartSessionRequest{
		Token:   "token1",
		Address: address.Hex(),
	})
	nonce := startSessionResponse.Data.(*types.StartSessionResponse).Nonce

	// When
	signature := signValue("wrong nonce", key)
	response, err := sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "token1",
		Signature: signature,
	})
	// Then
	require.Nil(t, err)
	require.True(t, response.Success)
	require.False(t, response.Data.(*types.AuthenticateResponse).Authenticated)

	// When
	wrongKey, _ := crypto.GenerateKey()
	signature = signValue(nonce, wrongKey)
	response, err = sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "token1",
		Signature: signature,
	})
	// Then
	require.Nil(t, err)
	require.True(t, response.Success)
	require.False(t, response.Data.(*types.AuthenticateResponse).Authenticated)

	// When
	signature = signValue(nonce, key)
	response, err = sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "wrong token",
		Signature: signature,
	})
	// Then
	require.Nil(t, err)
	require.False(t, response.Success)
	require.Equal(t, "no data found", response.Error)

	// When
	response, err = sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "token1",
		Signature: "wrong signature",
	})
	// Then
	require.Nil(t, err)
	require.True(t, response.Success)
	require.False(t, response.Data.(*types.AuthenticateResponse).Authenticated)

	// When
	signature = signValue(nonce, key)
	response, err = sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "token1",
		Signature: signature,
	})
	// Then
	require.Nil(t, err)
	require.True(t, response.Success)
	require.True(t, response.Data.(*types.AuthenticateResponse).Authenticated)
}

func Test_AuthenticateExpiredToken(t *testing.T) {
	s := startTestServer()
	defer s.Stop()

	key, _ := crypto.GenerateKey()
	address := crypto.PubkeyToAddress(key.PublicKey)
	startSessionResponse, _ := sendStartSessionRequest("v1", types.StartSessionRequest{
		Token:   "token1",
		Address: address.Hex(),
	})
	nonce := startSessionResponse.Data.(*types.StartSessionResponse).Nonce

	time.Sleep(time.Second * 11)

	// When
	signature := signValue(nonce, key)
	response, err := sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "token1",
		Signature: signature,
	})
	// Then
	require.Nil(t, err)
	require.False(t, response.Success)
	require.Equal(t, "no data found", response.Error)
}

func Test_GetAccount(t *testing.T) {
	s := startTestServer()
	defer s.Stop()

	key, _ := crypto.GenerateKey()
	address := crypto.PubkeyToAddress(key.PublicKey)
	startSessionResponse, _ := sendStartSessionRequest("v1", types.StartSessionRequest{
		Token:   "token1",
		Address: address.Hex(),
	})
	nonce := startSessionResponse.Data.(*types.StartSessionResponse).Nonce
	signature := signValue(nonce, key)
	sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "token1",
		Signature: signature,
	})

	// When
	response, err := sendGetAccountRequest("v1", "token1")
	// Then
	require.Nil(t, err)
	require.True(t, response.Success)
	require.Equal(t, address, common.HexToAddress(response.Data.(*types.GetAccountResponse).Address))

	// When
	response, err = sendGetAccountRequest("v1", "wrong-token")
	// Then
	require.Nil(t, err)
	require.False(t, response.Success)
	require.Equal(t, "no data found", response.Error)
}

func Test_Logout(t *testing.T) {
	s := startTestServer()
	defer s.Stop()

	key, _ := crypto.GenerateKey()
	address := crypto.PubkeyToAddress(key.PublicKey)
	startSessionResponse, _ := sendStartSessionRequest("v1", types.StartSessionRequest{
		Token:   "token1",
		Address: address.Hex(),
	})
	nonce := startSessionResponse.Data.(*types.StartSessionResponse).Nonce
	signature := signValue(nonce, key)
	sendAuthenticateRequest("v1", types.AuthenticateRequest{
		Token:     "token1",
		Signature: signature,
	})

	// When
	getAccountResponse1, _ := sendGetAccountRequest("v1", "token1")
	response, err := sendLogoutRequest("v1", types.LogoutRequest{
		Token: "token1",
	})
	getAccountResponse2, _ := sendGetAccountRequest("v1", "token1")
	// Then
	require.True(t, getAccountResponse1.Success)
	require.False(t, getAccountResponse2.Success)
	require.Nil(t, err)
	require.True(t, response.Success)
	require.True(t, response.Data.(*types.LogoutResponse).Loggedout)
}

func startTestServer() *Server {
	dbConnector, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	_, err = dbConnector.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
	if err != nil {
		panic(err)
	}
	_, err = dbConnector.Exec("CREATE SCHEMA " + schema)
	if err != nil {
		panic(err)
	}
	dbAccessor := postgres.NewAccessor(connStr+"&search_path="+schema, "../resources")
	auth := core.NewAuth(dbAccessor, time.Second*10, time.Second*20)
	server := NewServer(port, auth)
	go server.Start()
	return server
}

func sendStartSessionRequest(version string, request types.StartSessionRequest) (types.Response, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return types.Response{}, err
	}
	responseBytes, err := sendRequest(fmt.Sprintf("http://localhost:%d/%s/start-session", port, version), body)
	if err != nil {
		return types.Response{}, err
	}
	var startSessionResponse types.StartSessionResponse
	var response = types.Response{
		Data: &startSessionResponse,
	}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.Response{}, err
	}
	return response, nil
}

func sendAuthenticateRequest(version string, request types.AuthenticateRequest) (types.Response, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return types.Response{}, err
	}
	responseBytes, err := sendRequest(fmt.Sprintf("http://localhost:%d/%s/authenticate", port, version), body)
	if err != nil {
		return types.Response{}, err
	}
	var authenticateResponse types.AuthenticateResponse
	var response = types.Response{
		Data: &authenticateResponse,
	}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.Response{}, err
	}
	return response, nil
}

func sendGetAccountRequest(version string, token string) (types.Response, error) {
	responseBytes, err := sendRequest(fmt.Sprintf("http://localhost:%d/%s/get-account?token=%s", port, version, token), nil)
	if err != nil {
		return types.Response{}, err
	}
	var getAccountResponse types.GetAccountResponse
	var response = types.Response{
		Data: &getAccountResponse,
	}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.Response{}, err
	}
	return response, nil
}

func sendLogoutRequest(version string, request types.LogoutRequest) (types.Response, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return types.Response{}, err
	}
	responseBytes, err := sendRequest(fmt.Sprintf("http://localhost:%d/%s/logout", port, version), body)
	if err != nil {
		return types.Response{}, err
	}
	var logoutResponse types.LogoutResponse
	var response = types.Response{
		Data: &logoutResponse,
	}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.Response{}, err
	}
	return response, nil
}

func sendRequest(req string, body []byte) ([]byte, error) {
	var httpReq *http.Request
	var err error
	if body != nil {
		httpReq, err = http.NewRequest("POST", req, bytes.NewReader(body))
	} else {
		httpReq, err = http.NewRequest("GET", req, nil)
	}
	if err != nil {
		return nil, err
	}
	var resp *http.Response
	defer func() {
		if resp == nil || resp.Body == nil {
			return
		}
		resp.Body.Close()
	}()
	httpClient := &http.Client{
		Timeout: time.Second * 5,
	}
	resp, err = httpClient.Do(httpReq)
	if err == nil && resp.StatusCode != http.StatusOK {
		err = errors.New(fmt.Sprintf("resp code %v", resp.StatusCode))
	}
	if err != nil {
		return nil, err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read resp")
	}
	return respBody, nil
}

func signValue(value string, key *ecdsa.PrivateKey) string {
	buffer := memguard.NewBufferFromBytes(crypto.FromECDSA(key))
	hash := signatureHash(value)
	sec, _ := crypto.ToECDSA(buffer.Bytes())
	sig, _ := crypto.Sign(hash[:], sec)
	return hexutil.Encode(sig)
}

func signatureHash(value string) common.Hash {
	h := crypto.Hash([]byte(value))
	return crypto.Hash(h[:])
}
