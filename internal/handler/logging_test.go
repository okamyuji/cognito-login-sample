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
func newLoggingHandler(t *testing.T, c *fakeCognito, r *fakeRepo) (*Handler, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	h, err := New(c, r, &fakeVerifier{}, slog.New(slog.NewTextHandler(&logs, nil)), false, "")
	if err != nil {
		t.Fatalf("ハンドラの生成に失敗しました: %v", err)
	}
	return h, &logs
}

// TestRenderPageLogsOnlyOnTemplateError テンプレートの描画に失敗したときだけエラーログを出すことを検証する
func TestRenderPageLogsOnlyOnTemplateError(t *testing.T) {
	h, logs := newLoggingHandler(t, &fakeCognito{}, &fakeRepo{})

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
	h, logs := newLoggingHandler(t, &fakeCognito{}, &fakeRepo{findBySubErr: findErr})
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

// resendLogs 再送の結果を差し替えて再送を処理し、出力されたログを返す
func resendLogs(t *testing.T, resendErr error) string {
	t.Helper()
	h, logs := newLoggingHandler(t, &fakeCognito{resendErr: resendErr}, &fakeRepo{})
	req := httptest.NewRequest(http.MethodPost, "/api/resend", strings.NewReader("email=someone%40example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.resend(httptest.NewRecorder(), req)

	return logs.String()
}

// TestResendLogsOnlyCognitoErrors 再送の応答は結果によらず同じだが、Cognitoが拒否したときはログに残すことを検証する
func TestResendLogsOnlyCognitoErrors(t *testing.T) {
	if got := resendLogs(t, nil); got != "" {
		t.Errorf("再送に成功したのにログが出ています: %q", got)
	}
	if got := resendLogs(t, errors.New("network down")); !strings.Contains(got, "確認コードの再送を受け付けませんでした") {
		t.Errorf("再送の失敗がログに出ていません: %q", got)
	}
}

// TestValidEmailLengthBoundary メールアドレスは254文字まで受け付け、255文字は拒否することを検証する。
// ローカル部は RFC 5321 の上限64文字、ドメインのラベルは63文字以下にそろえ、長さ以外は正しい形にする
func TestValidEmailLengthBoundary(t *testing.T) {
	local := strings.Repeat("a", 64)
	domainOf := func(lastLabel int) string {
		return strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", lastLabel) + ".com"
	}
	at254 := local + "@" + domainOf(57)
	at255 := local + "@" + domainOf(58)
	if len(at254) != 254 || len(at255) != 255 {
		t.Fatalf("テストデータの長さが不正です: %d, %d", len(at254), len(at255))
	}

	if !validEmail(at254) {
		t.Errorf("254文字のメールアドレスが拒否されました")
	}
	if validEmail(at255) {
		t.Errorf("255文字のメールアドレスが受け付けられました")
	}
}
