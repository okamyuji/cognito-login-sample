package handler

import (
	"context"
	"net/http"

	"github.com/okamyuji/cognito-login-sample/internal/token"
)

// claimsKey コンテキストへ検証済みクレームを格納するためのキー型
type claimsKey struct{}

// claimsFrom コンテキストから検証済みクレームを取り出す
func claimsFrom(ctx context.Context) (*token.Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*token.Claims)
	return c, ok
}

// requireAuth セッションCookieのIDトークンを検証し、
// 無効な場合はログイン画面へリダイレクトするミドルウェア
func (h *Handler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		claims, err := h.verifier.Verify(r.Context(), cookie.Value)
		if err != nil {
			// 期限切れ・改ざんのいずれもセッション無効として扱い再ログインさせる
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}
