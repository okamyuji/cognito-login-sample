package handler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/okamyuji/cognito-login-sample/internal/repository"
	"github.com/okamyuji/cognito-login-sample/internal/token"
)

// newLoggingHandler ログの出力先をバッファに差し替えたハンドラを生成する
func newLoggingHandler(t *testing.T, r *fakeRepo) (*Handler, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	h, err := New(&fakeCognito{}, r, &fakeVerifier{}, slog.New(slog.NewTextHandler(&logs, nil)), false, "")
	if err != nil {
		t.Fatalf("ハンドラの生成に失敗しました: %v", err)
	}
	return h, &logs
}

// TestRenderPageLogsOnlyOnTemplateError テンプレートの描画に失敗したときだけエラーログを出すことを検証する
func TestRenderPageLogsOnlyOnTemplateError(t *testing.T) {
	h, logs := newLoggingHandler(t, &fakeRepo{})

	h.renderPage(httptest.NewRecorder(), "confirm_form", map[string]string{"Email": "someone@example.com"})
	if logs.Len() != 0 {
		t.Errorf("描画に成功したのにログが出ています: %q", logs.String())
	}

	h.renderPage(httptest.NewRecorder(), "no_such_template", nil)
	if !strings.Contains(logs.String(), "テンプレートの描画に失敗しました") {
		t.Errorf("描画の失敗がログに出ていません: %q", logs.String())
	}
}

// homeLogs 認証方式の取得結果を差し替えて保護ページを描画し、出力されたログを返す
func homeLogs(t *testing.T, findErr error) string {
	t.Helper()
	h, logs := newLoggingHandler(t, &fakeRepo{findBySubErr: findErr})
	claims := &token.Claims{Sub: "sub-1", Email: "someone@example.com"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey{}, claims))
	rec := httptest.NewRecorder()

	h.home(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("保護ページのステータス = %d, want %d", rec.Code, http.StatusOK)
	}
	return logs.String()
}

// TestHomeLogsOnlyUnexpectedRepoErrors 認証方式の取得で想定外のエラーが起きたときだけログを出すことを検証する。
// アプリDB未登録 (ErrNotFound) は正常な状態なのでログに出さない
func TestHomeLogsOnlyUnexpectedRepoErrors(t *testing.T) {
	if got := homeLogs(t, nil); got != "" {
		t.Errorf("取得に成功したのにログが出ています: %q", got)
	}
	if got := homeLogs(t, repository.ErrNotFound); got != "" {
		t.Errorf("アプリDB未登録なのにログが出ています: %q", got)
	}
	if got := homeLogs(t, errors.New("db down")); !strings.Contains(got, "認証方式の取得に失敗しました") {
		t.Errorf("取得の失敗がログに出ていません: %q", got)
	}
}

// TestValidEmailLengthBoundary メールアドレスは254文字まで受け付け、255文字は拒否することを検証する
func TestValidEmailLengthBoundary(t *testing.T) {
	const domain = "@example.com"
	at254 := strings.Repeat("a", 254-len(domain)) + domain
	at255 := "a" + at254

	if !validEmail(at254) {
		t.Errorf("254文字のメールアドレスが拒否されました")
	}
	if validEmail(at255) {
		t.Errorf("255文字のメールアドレスが受け付けられました")
	}
}
