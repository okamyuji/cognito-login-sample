package cognito

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInitiateAuthRequestShape 実APIと同じ形式のリクエストを組み立てることを検証する。
// HTTP層で受け取った内容 (ヘッダ・ボディ) を実際に検査し、
// クライアント実装の思い込みがテストに写らないようにする
func TestInitiateAuthRequestShape(t *testing.T) {
	var gotTarget, gotContentType string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTarget = r.Header.Get("X-Amz-Target")
		gotContentType = r.Header.Get("Content-Type")
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("リクエストボディの読み取りに失敗しました: %v", err)
		}
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("リクエストボディの解釈に失敗しました: %v", err)
		}
		// 実Cognitoが返すレスポンスと同じ形のJSONを返す
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if _, err := w.Write([]byte(`{
			"AuthenticationResult": {
				"IdToken": "id-token-value",
				"AccessToken": "access-token-value",
				"RefreshToken": "refresh-token-value",
				"ExpiresIn": 3600,
				"TokenType": "Bearer"
			}
		}`)); err != nil {
			t.Errorf("レスポンスの書き込みに失敗しました: %v", err)
		}
	}))
	defer srv.Close()

	c := NewHTTPClientWithEndpoint(srv.URL, "test-client-id", "test-secret")
	result, err := c.InitiateAuth(context.Background(), "user@example.com", "Passw0rd!")
	if err != nil {
		t.Fatalf("InitiateAuth() error = %v", err)
	}

	if gotTarget != "AWSCognitoIdentityProviderService.InitiateAuth" {
		t.Errorf("X-Amz-Target = %q, want %q", gotTarget, "AWSCognitoIdentityProviderService.InitiateAuth")
	}
	if gotContentType != "application/x-amz-json-1.1" {
		t.Errorf("Content-Type = %q, want %q", gotContentType, "application/x-amz-json-1.1")
	}
	if gotBody["ClientId"] != "test-client-id" {
		t.Errorf("ClientId = %v, want %q", gotBody["ClientId"], "test-client-id")
	}
	if gotBody["AuthFlow"] != "USER_PASSWORD_AUTH" {
		t.Errorf("AuthFlow = %v, want %q", gotBody["AuthFlow"], "USER_PASSWORD_AUTH")
	}
	params, ok := gotBody["AuthParameters"].(map[string]any)
	if !ok {
		t.Fatalf("AuthParametersが送信されていません: %v", gotBody)
	}
	if params["USERNAME"] != "user@example.com" {
		t.Errorf("USERNAME = %v, want %q", params["USERNAME"], "user@example.com")
	}
	if params["PASSWORD"] != "Passw0rd!" {
		t.Errorf("PASSWORD = %v, want %q", params["PASSWORD"], "Passw0rd!")
	}
	wantHash := ComputeSecretHash("user@example.com", "test-client-id", "test-secret")
	if params["SECRET_HASH"] != wantHash {
		t.Errorf("SECRET_HASH = %v, want %q", params["SECRET_HASH"], wantHash)
	}

	// 戻り値の中身まで検証する
	if result.IDToken != "id-token-value" {
		t.Errorf("IDToken = %q, want %q", result.IDToken, "id-token-value")
	}
	if result.AccessToken != "access-token-value" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "access-token-value")
	}
	if result.RefreshToken != "refresh-token-value" {
		t.Errorf("RefreshToken = %q, want %q", result.RefreshToken, "refresh-token-value")
	}
	if result.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", result.ExpiresIn)
	}
}

// TestSignUpRequestShape SignUpのリクエスト形式とメール属性の送信を検証する
func TestSignUpRequestShape(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("リクエストボディの読み取りに失敗しました: %v", err)
		}
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("リクエストボディの解釈に失敗しました: %v", err)
		}
		if _, err := w.Write([]byte(`{"UserConfirmed": false, "UserSub": "sub-1234"}`)); err != nil {
			t.Errorf("レスポンスの書き込みに失敗しました: %v", err)
		}
	}))
	defer srv.Close()

	c := NewHTTPClientWithEndpoint(srv.URL, "test-client-id", "test-secret")
	if err := c.SignUp(context.Background(), "user@example.com", "Passw0rd!"); err != nil {
		t.Fatalf("SignUp() error = %v", err)
	}

	attrs, ok := gotBody["UserAttributes"].([]any)
	if !ok || len(attrs) != 1 {
		t.Fatalf("UserAttributes = %v, want 1件", gotBody["UserAttributes"])
	}
	attr, ok := attrs[0].(map[string]any)
	if !ok {
		t.Fatalf("UserAttributes[0]の型が不正です: %T", attrs[0])
	}
	if attr["Name"] != "email" || attr["Value"] != "user@example.com" {
		t.Errorf("email属性 = %v, want Name=email Value=user@example.com", attr)
	}
}

// TestErrorMapping 実Cognitoが返すエラーボディを各エラー値へ対応付けることを検証する。
// __typeにサービス名前空間の接頭辞が付く形式も実挙動に合わせて含める
func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{
			name:    "NotAuthorizedExceptionはErrNotAuthorizedになる",
			status:  400,
			body:    `{"__type":"NotAuthorizedException","message":"Incorrect username or password."}`,
			wantErr: ErrNotAuthorized,
		},
		{
			name:    "名前空間接頭辞付きの__typeも対応付けられる",
			status:  400,
			body:    `{"__type":"com.amazonaws.cognito#NotAuthorizedException","message":"Incorrect username or password."}`,
			wantErr: ErrNotAuthorized,
		},
		{
			name:    "UserNotFoundExceptionはErrUserNotFoundになる",
			status:  400,
			body:    `{"__type":"UserNotFoundException","message":"User does not exist."}`,
			wantErr: ErrUserNotFound,
		},
		{
			name:    "UserNotConfirmedExceptionはErrUserNotConfirmedになる",
			status:  400,
			body:    `{"__type":"UserNotConfirmedException","message":"User is not confirmed."}`,
			wantErr: ErrUserNotConfirmed,
		},
		{
			name:    "UsernameExistsExceptionはErrUsernameExistsになる",
			status:  400,
			body:    `{"__type":"UsernameExistsException","message":"An account with the given email already exists."}`,
			wantErr: ErrUsernameExists,
		},
		{
			name:    "InvalidPasswordExceptionはErrInvalidPasswordになる",
			status:  400,
			body:    `{"__type":"InvalidPasswordException","message":"Password did not conform with policy"}`,
			wantErr: ErrInvalidPassword,
		},
		{
			name:    "CodeMismatchExceptionはErrCodeMismatchになる",
			status:  400,
			body:    `{"__type":"CodeMismatchException","message":"Invalid verification code provided"}`,
			wantErr: ErrCodeMismatch,
		},
		{
			name:    "ExpiredCodeExceptionはErrExpiredCodeになる",
			status:  400,
			body:    `{"__type":"ExpiredCodeException","message":"Invalid code provided"}`,
			wantErr: ErrExpiredCode,
		},
		{
			name:    "TooManyRequestsExceptionはErrLimitExceededになる",
			status:  400,
			body:    `{"__type":"TooManyRequestsException","message":"Rate exceeded"}`,
			wantErr: ErrLimitExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				if _, err := w.Write([]byte(tt.body)); err != nil {
					t.Errorf("レスポンスの書き込みに失敗しました: %v", err)
				}
			}))
			defer srv.Close()

			c := NewHTTPClientWithEndpoint(srv.URL, "cid", "secret")
			_, err := c.InitiateAuth(context.Background(), "user@example.com", "pw")
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("InitiateAuth() error = %v, want errors.Is(err, %v)", err, tt.wantErr)
			}
		})
	}
}

// TestUnknownErrorNotSwallowed 未知のエラー型でもエラーとして返り、黙殺されないことを検証する
func TestUnknownErrorNotSwallowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		if _, err := w.Write([]byte(`{"__type":"InternalErrorException","message":"boom"}`)); err != nil {
			t.Errorf("レスポンスの書き込みに失敗しました: %v", err)
		}
	}))
	defer srv.Close()

	c := NewHTTPClientWithEndpoint(srv.URL, "cid", "secret")
	_, err := c.InitiateAuth(context.Background(), "user@example.com", "pw")
	if err == nil {
		t.Fatal("InitiateAuth() error = nil, want エラー")
	}
}
