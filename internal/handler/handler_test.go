package handler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/okamyuji/cognito-login-sample/internal/cognito"
	"github.com/okamyuji/cognito-login-sample/internal/repository"
	"github.com/okamyuji/cognito-login-sample/internal/token"
)

// fakeCognito cognito.Clientの偽実装。呼び出し内容を記録し、指定した結果を返す
type fakeCognito struct {
	signUpErr      error
	confirmErr     error
	initiateResult *cognito.AuthResult
	initiateErr    error
	initiateCalled bool
	signUpCalled   bool
	signUpEmail    string
	confirmedEmail string
	confirmedCode  string
	initiateEmail  string
	initiatePasswd string
}

func (f *fakeCognito) SignUp(_ context.Context, email, _ string) error {
	f.signUpCalled = true
	f.signUpEmail = email
	return f.signUpErr
}

func (f *fakeCognito) ConfirmSignUp(_ context.Context, email, code string) error {
	f.confirmedEmail = email
	f.confirmedCode = code
	return f.confirmErr
}

func (f *fakeCognito) InitiateAuth(_ context.Context, email, password string) (*cognito.AuthResult, error) {
	f.initiateCalled = true
	f.initiateEmail = email
	f.initiatePasswd = password
	return f.initiateResult, f.initiateErr
}

// fakeRepo repository.UserRepositoryの偽実装
type fakeRepo struct {
	findByEmailUser    *repository.User
	findByEmailMethods []repository.AuthMethod
	findByEmailErr     error
	findBySubUser      *repository.User
	findBySubMethods   []repository.AuthMethod
	findBySubErr       error
	upsertedUser       *repository.User
	upsertedMethod     *repository.AuthMethod
	upsertErr          error
}

func (f *fakeRepo) UpsertUserWithMethod(_ context.Context, user repository.User, method repository.AuthMethod) error {
	f.upsertedUser = &user
	f.upsertedMethod = &method
	return f.upsertErr
}

func (f *fakeRepo) FindByEmail(_ context.Context, _ string) (*repository.User, []repository.AuthMethod, error) {
	return f.findByEmailUser, f.findByEmailMethods, f.findByEmailErr
}

func (f *fakeRepo) FindBySub(_ context.Context, _ string) (*repository.User, []repository.AuthMethod, error) {
	return f.findBySubUser, f.findBySubMethods, f.findBySubErr
}

// fakeVerifier token.Verifierの偽実装。特定のトークン文字列のみを受理する
type fakeVerifier struct {
	acceptToken string
	claims      *token.Claims
}

func (f *fakeVerifier) Verify(_ context.Context, rawToken string) (*token.Claims, error) {
	if rawToken == f.acceptToken {
		return f.claims, nil
	}
	return nil, token.ErrInvalidToken
}

// testStatic テスト用の最小静的ファイルシステム
var testStatic = fstest.MapFS{
	"style.css": &fstest.MapFile{Data: []byte("body{}")},
}

// newTestServer 偽実装を注入したハンドラのテストサーバを起動する
func newTestServer(t *testing.T, c *fakeCognito, r *fakeRepo, v *fakeVerifier) *httptest.Server {
	t.Helper()
	h, err := New(c, r, v, slog.New(slog.NewTextHandler(io.Discard, nil)), false, "")
	if err != nil {
		t.Fatalf("ハンドラの生成に失敗しました: %v", err)
	}
	srv := httptest.NewServer(h.Routes(testStatic))
	t.Cleanup(srv.Close)
	return srv
}

// noRedirectClient リダイレクトを追跡しないHTTPクライアントを返す
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// postForm 同一オリジンからのフォーム送信を模したPOSTを送る
func postForm(t *testing.T, srv *httptest.Server, path string, values url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("リクエストの生成に失敗しました: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("リクエストの送信に失敗しました: %v", err)
	}
	t.Cleanup(func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("レスポンスのクローズに失敗しました: %v", cerr)
		}
	})
	return resp
}

// readBody レスポンスボディを文字列として読み取る
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ボディの読み取りに失敗しました: %v", err)
	}
	return string(raw)
}

// TestLoginSuccess ログイン成功でCookieが設定されホームへ誘導されることを検証する。
// あわせてアプリDBへsub・メール・password方式が記録されることまで確認する
func TestLoginSuccess(t *testing.T) {
	c := &fakeCognito{initiateResult: &cognito.AuthResult{IDToken: "good-token", ExpiresIn: 3600}}
	r := &fakeRepo{findByEmailErr: repository.ErrNotFound}
	v := &fakeVerifier{
		acceptToken: "good-token",
		claims:      &token.Claims{Sub: "sub-1234", Email: "user@example.com"},
	}
	srv := newTestServer(t, c, r, v)

	resp := postForm(t, srv, "/api/login", url.Values{
		"email":    {"user@example.com"},
		"password": {"Passw0rd!"},
	})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("HX-Redirect"); got != "/" {
		t.Errorf("HX-Redirect = %q, want %q", got, "/")
	}
	var sessionCookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookieName {
			sessionCookie = ck
		}
	}
	if sessionCookie == nil {
		t.Fatal("セッションCookieが設定されていません")
	}
	if sessionCookie.Value != "good-token" {
		t.Errorf("Cookie値 = %q, want %q", sessionCookie.Value, "good-token")
	}
	if !sessionCookie.HttpOnly {
		t.Error("CookieにHttpOnlyが付いていません")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", sessionCookie.SameSite)
	}
	if sessionCookie.MaxAge != 3600 {
		t.Errorf("MaxAge = %d, want 3600", sessionCookie.MaxAge)
	}
	if r.upsertedUser == nil || r.upsertedUser.Sub != "sub-1234" || r.upsertedUser.Email != "user@example.com" {
		t.Errorf("登録されたユーザー = %+v, want sub-1234 / user@example.com", r.upsertedUser)
	}
	if r.upsertedMethod == nil || r.upsertedMethod.Method != repository.MethodPassword {
		t.Errorf("登録された認証方式 = %+v, want password", r.upsertedMethod)
	}
}

// TestLoginGoogleOnlyAccount Google連携のみのアカウントにパスワード経路を案内で遮断することを検証する。
// このときCognitoへの認証問い合わせが発生しないことまで確認する (home realm discoveryの実演)
func TestLoginGoogleOnlyAccount(t *testing.T) {
	c := &fakeCognito{}
	r := &fakeRepo{
		findByEmailUser: &repository.User{Sub: "sub-g", Email: "user@example.com"},
		findByEmailMethods: []repository.AuthMethod{
			{UserSub: "sub-g", Method: repository.MethodGoogle, ProviderSub: "google-oauth2|111"},
		},
	}
	srv := newTestServer(t, c, r, &fakeVerifier{})

	resp := postForm(t, srv, "/api/login", url.Values{
		"email":    {"user@example.com"},
		"password": {"whatever"},
	})

	body := readBody(t, resp)
	if !strings.Contains(body, "Googleログインで作成されています") {
		t.Errorf("Google経路への案内が表示されていません: %q", body)
	}
	if c.initiateCalled {
		t.Error("Google連携のみのアカウントに対してCognitoへ認証問い合わせが発生しています")
	}
}

// TestLoginPasswordAndGoogleAccount 両方式を持つ統合済みアカウントはパスワードでもログインできることを検証する
func TestLoginPasswordAndGoogleAccount(t *testing.T) {
	c := &fakeCognito{initiateResult: &cognito.AuthResult{IDToken: "good-token", ExpiresIn: 3600}}
	r := &fakeRepo{
		findByEmailUser: &repository.User{Sub: "sub-1234", Email: "user@example.com"},
		findByEmailMethods: []repository.AuthMethod{
			{UserSub: "sub-1234", Method: repository.MethodPassword},
			{UserSub: "sub-1234", Method: repository.MethodGoogle, ProviderSub: "google-oauth2|111"},
		},
	}
	v := &fakeVerifier{
		acceptToken: "good-token",
		claims:      &token.Claims{Sub: "sub-1234", Email: "user@example.com"},
	}
	srv := newTestServer(t, c, r, v)

	resp := postForm(t, srv, "/api/login", url.Values{
		"email":    {"user@example.com"},
		"password": {"Passw0rd!"},
	})

	if got := resp.Header.Get("HX-Redirect"); got != "/" {
		t.Errorf("HX-Redirect = %q, want %q", got, "/")
	}
	if !c.initiateCalled {
		t.Error("パスワード方式を持つアカウントなのにCognitoへの認証問い合わせが発生していません")
	}
}

// TestLoginFailures ログイン失敗系の表示をテーブル駆動で検証する
func TestLoginFailures(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		password    string
		initiateErr error
		wantText    string
	}{
		{
			name:        "パスワード不一致で汎用メッセージを表示する",
			email:       "user@example.com",
			password:    "wrong",
			initiateErr: cognito.ErrNotAuthorized,
			wantText:    genericLoginFailure,
		},
		{
			name:        "ユーザー不存在でも同じ汎用メッセージを表示する (列挙防止)",
			email:       "nobody@example.com",
			password:    "whatever",
			initiateErr: cognito.ErrUserNotFound,
			wantText:    genericLoginFailure,
		},
		{
			name:        "試行上限超過で待機を案内する",
			email:       "user@example.com",
			password:    "pw",
			initiateErr: cognito.ErrLimitExceeded,
			wantText:    "試行回数が上限を超えました",
		},
		{
			name:     "メールアドレス空で入力を促す",
			email:    "",
			password: "pw",
			wantText: "メールアドレスとパスワードを入力してください",
		},
		{
			name:     "メールアドレス形式不正で入力を促す",
			email:    "not-an-email",
			password: "pw",
			wantText: "メールアドレスとパスワードを入力してください",
		},
		{
			name:     "パスワード空で入力を促す",
			email:    "user@example.com",
			password: "",
			wantText: "メールアドレスとパスワードを入力してください",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &fakeCognito{initiateErr: tt.initiateErr}
			r := &fakeRepo{findByEmailErr: repository.ErrNotFound}
			srv := newTestServer(t, c, r, &fakeVerifier{})

			resp := postForm(t, srv, "/api/login", url.Values{
				"email":    {tt.email},
				"password": {tt.password},
			})
			body := readBody(t, resp)
			if !strings.Contains(body, tt.wantText) {
				t.Errorf("body = %q, want %qを含む", body, tt.wantText)
			}
			if resp.Header.Get("HX-Redirect") != "" {
				t.Error("失敗時にリダイレクトが発生しています")
			}
			for _, ck := range resp.Cookies() {
				if ck.Name == sessionCookieName {
					t.Error("失敗時にセッションCookieが設定されています")
				}
			}
		})
	}
}

// TestLoginUnconfirmedShowsConfirmForm 未確認ユーザーのログインで確認コード入力へ誘導することを検証する
func TestLoginUnconfirmedShowsConfirmForm(t *testing.T) {
	c := &fakeCognito{initiateErr: cognito.ErrUserNotConfirmed}
	r := &fakeRepo{findByEmailErr: repository.ErrNotFound}
	srv := newTestServer(t, c, r, &fakeVerifier{})

	resp := postForm(t, srv, "/api/login", url.Values{
		"email":    {"user@example.com"},
		"password": {"Passw0rd!"},
	})
	body := readBody(t, resp)
	if !strings.Contains(body, "確認コード") {
		t.Errorf("確認コードフォームが表示されていません: %q", body)
	}
	if !strings.Contains(body, `value="user@example.com"`) {
		t.Errorf("確認フォームにメールアドレスが引き継がれていません: %q", body)
	}
}

// TestProtectedPageRedirectsWithoutSession 未ログインで保護ページへアクセスするとログイン画面へ誘導されることを検証する
func TestProtectedPageRedirectsWithoutSession(t *testing.T) {
	srv := newTestServer(t, &fakeCognito{}, &fakeRepo{}, &fakeVerifier{})

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("リクエストの生成に失敗しました: %v", err)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("リクエストの送信に失敗しました: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("レスポンスのクローズに失敗しました: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want %q", got, "/login")
	}
}

// TestProtectedPageRejectsInvalidToken 改ざん・期限切れ相当の無効トークンでは保護ページを表示しないことを検証する
func TestProtectedPageRejectsInvalidToken(t *testing.T) {
	v := &fakeVerifier{acceptToken: "good-token", claims: &token.Claims{Sub: "s", Email: "e@example.com"}}
	srv := newTestServer(t, &fakeCognito{}, &fakeRepo{}, v)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("リクエストの生成に失敗しました: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "tampered-token"})
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("リクエストの送信に失敗しました: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("レスポンスのクローズに失敗しました: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
}

// TestProtectedPageShowsProfile 有効なセッションで保護ページにプロフィールと認証方式が表示されることを検証する
func TestProtectedPageShowsProfile(t *testing.T) {
	v := &fakeVerifier{
		acceptToken: "good-token",
		claims:      &token.Claims{Sub: "sub-1234", Email: "user@example.com"},
	}
	r := &fakeRepo{
		findBySubUser: &repository.User{Sub: "sub-1234", Email: "user@example.com"},
		findBySubMethods: []repository.AuthMethod{
			{UserSub: "sub-1234", Method: repository.MethodPassword},
		},
	}
	srv := newTestServer(t, &fakeCognito{}, r, v)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("リクエストの生成に失敗しました: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "good-token"})
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("リクエストの送信に失敗しました: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("レスポンスのクローズに失敗しました: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "user@example.com") {
		t.Errorf("メールアドレスが表示されていません: %q", body)
	}
	if !strings.Contains(body, "sub-1234") {
		t.Errorf("subが表示されていません: %q", body)
	}
	if !strings.Contains(body, "password") {
		t.Errorf("認証方式が表示されていません: %q", body)
	}
}

// TestSignupShowsConfirmForm 仮登録成功で確認コードフォームが表示されることを検証する
func TestSignupShowsConfirmForm(t *testing.T) {
	c := &fakeCognito{}
	srv := newTestServer(t, c, &fakeRepo{}, &fakeVerifier{})

	resp := postForm(t, srv, "/api/signup", url.Values{
		"email":    {"new@example.com"},
		"password": {"Passw0rd!"},
	})
	body := readBody(t, resp)
	if !strings.Contains(body, "確認コード") {
		t.Errorf("確認コードフォームが表示されていません: %q", body)
	}
	if c.signUpEmail != "new@example.com" {
		t.Errorf("SignUpへ渡されたメール = %q, want new@example.com", c.signUpEmail)
	}
}

// TestSignupGoogleOnlyAccountGuided Google連携のみのメールでの登録を案内で遮断することを検証する。
// このときCognitoへのSignUp呼び出しが発生しないことまで確認する
func TestSignupGoogleOnlyAccountGuided(t *testing.T) {
	c := &fakeCognito{}
	r := &fakeRepo{
		findByEmailUser: &repository.User{Sub: "sub-g", Email: "demo-google@example.com"},
		findByEmailMethods: []repository.AuthMethod{
			{UserSub: "sub-g", Method: repository.MethodGoogle, ProviderSub: "google-oauth2|111"},
		},
	}
	srv := newTestServer(t, c, r, &fakeVerifier{})

	resp := postForm(t, srv, "/api/signup", url.Values{
		"email":    {"demo-google@example.com"},
		"password": {"Passw0rd!"},
	})
	body := readBody(t, resp)
	if !strings.Contains(body, "Googleログインで作成されています") {
		t.Errorf("Google経路への案内が表示されていません: %q", body)
	}
	if c.signUpCalled {
		t.Error("Google連携のみのメールに対してCognitoへSignUpが発生しています")
	}
}

// TestGoogleLoginRedirectsWhenConfigured authorize URL設定時にGoogleボタンがリダイレクトすることを検証する
func TestGoogleLoginRedirectsWhenConfigured(t *testing.T) {
	h, err := New(&fakeCognito{}, &fakeRepo{}, &fakeVerifier{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), false,
		"https://auth.example.com/oauth2/authorize?identity_provider=Google")
	if err != nil {
		t.Fatalf("ハンドラの生成に失敗しました: %v", err)
	}
	srv := httptest.NewServer(h.Routes(testStatic))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/auth/google", nil)
	if err != nil {
		t.Fatalf("リクエストの生成に失敗しました: %v", err)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("リクエストの送信に失敗しました: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("レスポンスのクローズに失敗しました: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	want := "https://auth.example.com/oauth2/authorize?identity_provider=Google"
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

// TestGoogleLoginUnconfiguredShowsNotice authorize URL未設定時に案内が表示されることを検証する
func TestGoogleLoginUnconfiguredShowsNotice(t *testing.T) {
	srv := newTestServer(t, &fakeCognito{}, &fakeRepo{}, &fakeVerifier{})

	resp, err := noRedirectClient().Get(srv.URL + "/auth/google")
	if err != nil {
		t.Fatalf("リクエストの送信に失敗しました: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("レスポンスのクローズに失敗しました: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "Google連携を設定していません") {
		t.Errorf("未設定の案内が表示されていません: %q", body)
	}
}

// TestSignupExistingUserNonCommittal 登録済みメールでも存在を断定しない文言を返すことを検証する (列挙防止)
func TestSignupExistingUserNonCommittal(t *testing.T) {
	c := &fakeCognito{signUpErr: cognito.ErrUsernameExists}
	srv := newTestServer(t, c, &fakeRepo{}, &fakeVerifier{})

	resp := postForm(t, srv, "/api/signup", url.Values{
		"email":    {"existing@example.com"},
		"password": {"Passw0rd!"},
	})
	body := readBody(t, resp)
	if !strings.Contains(body, "登録を受け付けられませんでした") {
		t.Errorf("非断定の文言が表示されていません: %q", body)
	}
}

// TestConfirmSuccess 確認コードの受理で完了メッセージが表示されることを検証する
func TestConfirmSuccess(t *testing.T) {
	c := &fakeCognito{}
	srv := newTestServer(t, c, &fakeRepo{}, &fakeVerifier{})

	resp := postForm(t, srv, "/api/confirm", url.Values{
		"email": {"new@example.com"},
		"code":  {"123456"},
	})
	body := readBody(t, resp)
	if !strings.Contains(body, "登録が完了しました") {
		t.Errorf("完了メッセージが表示されていません: %q", body)
	}
	if c.confirmedEmail != "new@example.com" || c.confirmedCode != "123456" {
		t.Errorf("ConfirmSignUpへの引数 = (%q, %q), want (new@example.com, 123456)", c.confirmedEmail, c.confirmedCode)
	}
}

// TestLogoutClearsCookie ログアウトでセッションCookieが破棄されることを検証する
func TestLogoutClearsCookie(t *testing.T) {
	srv := newTestServer(t, &fakeCognito{}, &fakeRepo{}, &fakeVerifier{})

	resp := postForm(t, srv, "/api/logout", url.Values{})
	if got := resp.Header.Get("HX-Redirect"); got != "/login" {
		t.Errorf("HX-Redirect = %q, want %q", got, "/login")
	}
	var cleared bool
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("セッションCookieが破棄されていません")
	}
}

// TestCrossSitePostRejected クロスサイトからの状態変更POSTが遮断されることを検証する (CSRF対策)
func TestCrossSitePostRejected(t *testing.T) {
	srv := newTestServer(t, &fakeCognito{}, &fakeRepo{}, &fakeVerifier{})

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/logout", strings.NewReader(""))
	if err != nil {
		t.Fatalf("リクエストの生成に失敗しました: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("リクエストの送信に失敗しました: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("レスポンスのクローズに失敗しました: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestRepoFailureDoesNotLeakDetails リポジトリ障害時に内部情報を漏らさない汎用メッセージを返し、Cognitoへ問い合わせないことを検証する
func TestRepoFailureDoesNotLeakDetails(t *testing.T) {
	c := &fakeCognito{}
	r := &fakeRepo{findByEmailErr: errors.New("dial tcp 10.0.0.5:3306: connection refused")}
	srv := newTestServer(t, c, r, &fakeVerifier{})

	resp := postForm(t, srv, "/api/login", url.Values{
		"email":    {"user@example.com"},
		"password": {"pw"},
	})
	body := readBody(t, resp)
	if strings.Contains(body, "10.0.0.5") {
		t.Errorf("内部エラーの詳細が漏れています: %q", body)
	}
	if !strings.Contains(body, "一時的なエラーが発生しました") {
		t.Errorf("汎用メッセージが表示されていません: %q", body)
	}
	if c.initiateCalled {
		t.Error("リポジトリ障害時にCognitoへ認証問い合わせが発生しています")
	}
}
