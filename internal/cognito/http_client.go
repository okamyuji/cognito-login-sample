package cognito

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// amzTarget Cognito Identity Provider APIのX-Amz-Targetヘッダ接頭辞
const amzTarget = "AWSCognitoIdentityProviderService."

// HTTPClient 標準ライブラリのみでCognito Identity Provider APIを呼び出す実装。
// SignUp / ConfirmSignUp / InitiateAuth (USER_PASSWORD_AUTH) は署名不要の
// 匿名APIのため、SigV4署名なしのHTTPS POSTで完結する
type HTTPClient struct {
	endpoint     string
	clientID     string
	clientSecret string
	httpc        *http.Client
}

// NewHTTPClient リージョンとアプリクライアント情報からHTTPClientを生成する
func NewHTTPClient(region, clientID, clientSecret string) *HTTPClient {
	return &HTTPClient{
		endpoint:     fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/", region),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpc:        &http.Client{Timeout: 10 * time.Second},
	}
}

// NewHTTPClientWithEndpoint テスト用にエンドポイントを差し替えてHTTPClientを生成する
func NewHTTPClientWithEndpoint(endpoint, clientID, clientSecret string) *HTTPClient {
	c := NewHTTPClient("dummy", clientID, clientSecret)
	c.endpoint = endpoint
	return c
}

// apiError Cognito APIがエラー時に返すJSONボディ
type apiError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

// SignUp メールアドレスとパスワードでユーザーを仮登録する
func (c *HTTPClient) SignUp(ctx context.Context, email, password string) error {
	req := map[string]any{
		"ClientId":   c.clientID,
		"SecretHash": ComputeSecretHash(email, c.clientID, c.clientSecret),
		"Username":   email,
		"Password":   password,
		"UserAttributes": []map[string]string{
			{"Name": "email", "Value": email},
		},
	}
	return c.call(ctx, "SignUp", req, nil)
}

// ConfirmSignUp 確認コードにより仮登録を本登録へ昇格する
func (c *HTTPClient) ConfirmSignUp(ctx context.Context, email, code string) error {
	req := map[string]any{
		"ClientId":         c.clientID,
		"SecretHash":       ComputeSecretHash(email, c.clientID, c.clientSecret),
		"Username":         email,
		"ConfirmationCode": code,
	}
	return c.call(ctx, "ConfirmSignUp", req, nil)
}

// initiateAuthResponse InitiateAuth成功時のレスポンスボディ
type initiateAuthResponse struct {
	AuthenticationResult struct {
		IdToken      string `json:"IdToken"`
		AccessToken  string `json:"AccessToken"`
		RefreshToken string `json:"RefreshToken"`
		ExpiresIn    int    `json:"ExpiresIn"`
	} `json:"AuthenticationResult"`
	ChallengeName string `json:"ChallengeName"`
}

// InitiateAuth USER_PASSWORD_AUTHフローで認証しトークン一式を得る
func (c *HTTPClient) InitiateAuth(ctx context.Context, email, password string) (*AuthResult, error) {
	req := map[string]any{
		"ClientId": c.clientID,
		"AuthFlow": "USER_PASSWORD_AUTH",
		"AuthParameters": map[string]string{
			"USERNAME":    email,
			"PASSWORD":    password,
			"SECRET_HASH": ComputeSecretHash(email, c.clientID, c.clientSecret),
		},
	}
	var resp initiateAuthResponse
	if err := c.call(ctx, "InitiateAuth", req, &resp); err != nil {
		return nil, err
	}
	if resp.AuthenticationResult.IdToken == "" {
		// MFA等のチャレンジ応答が必要な設定の場合、本サンプルの範囲外として扱う
		return nil, fmt.Errorf("cognito: 未対応のチャレンジが要求されました: %s", resp.ChallengeName)
	}
	return &AuthResult{
		IDToken:      resp.AuthenticationResult.IdToken,
		AccessToken:  resp.AuthenticationResult.AccessToken,
		RefreshToken: resp.AuthenticationResult.RefreshToken,
		ExpiresIn:    resp.AuthenticationResult.ExpiresIn,
	}, nil
}

// call 指定オペレーションへx-amz-json-1.1形式でPOSTし、エラーレスポンスを判別する
func (c *HTTPClient) call(ctx context.Context, operation string, body any, out any) (err error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("cognito: リクエストの組み立てに失敗しました: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("cognito: リクエストの生成に失敗しました: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", amzTarget+operation)

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("cognito: APIの呼び出しに失敗しました: %w", err)
	}
	defer func() {
		// レスポンスボディは読了済みのためCloseの失敗は接続再利用にのみ影響する。
		// それでもエラーを黙殺しない方針に従い、発生時はエラーとして返す値へ合流させる
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("cognito: レスポンスのクローズに失敗しました: %w", cerr)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("cognito: レスポンスの読み取りに失敗しました: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var ae apiError
		if uerr := json.Unmarshal(raw, &ae); uerr != nil {
			return fmt.Errorf("cognito: APIエラー (status=%d, body=%.200s)", resp.StatusCode, string(raw))
		}
		return mapAPIError(ae)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("cognito: レスポンスの解釈に失敗しました: %w", err)
		}
	}
	return nil
}

// mapAPIError Cognitoの__typeフィールドをパッケージ内のエラー値へ対応付ける
func mapAPIError(ae apiError) error {
	// __typeにサービス名前空間の接頭辞が付く場合があるため末尾の型名だけを比較する
	t := ae.Type
	if i := strings.LastIndex(t, "#"); i >= 0 {
		t = t[i+1:]
	}
	switch t {
	case "NotAuthorizedException":
		return fmt.Errorf("%w: %s", ErrNotAuthorized, ae.Message)
	case "UserNotFoundException":
		return fmt.Errorf("%w: %s", ErrUserNotFound, ae.Message)
	case "UserNotConfirmedException":
		return fmt.Errorf("%w: %s", ErrUserNotConfirmed, ae.Message)
	case "UsernameExistsException":
		return fmt.Errorf("%w: %s", ErrUsernameExists, ae.Message)
	case "InvalidPasswordException", "InvalidParameterException":
		return fmt.Errorf("%w: %s", ErrInvalidPassword, ae.Message)
	case "CodeMismatchException":
		return fmt.Errorf("%w: %s", ErrCodeMismatch, ae.Message)
	case "ExpiredCodeException":
		return fmt.Errorf("%w: %s", ErrExpiredCode, ae.Message)
	case "LimitExceededException", "TooManyRequestsException":
		return fmt.Errorf("%w: %s", ErrLimitExceeded, ae.Message)
	default:
		return fmt.Errorf("cognito: APIエラー (%s): %s", ae.Type, ae.Message)
	}
}
