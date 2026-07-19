package handler

import (
	"errors"
	"net/http"

	"github.com/okamyuji/cognito-login-sample/internal/repository"
)

// loginPage ログイン画面を表示する
func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "login", nil)
}

// signupPage 新規登録画面を表示する
func (h *Handler) signupPage(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "signup", nil)
}

// homeData ホーム画面の描画に使うデータ
type homeData struct {
	// Email ログイン中ユーザーのメールアドレス
	Email string
	// Sub ログイン中ユーザーのCognito sub
	Sub string
	// Methods アプリDBに記録された認証方式一覧
	Methods []repository.AuthMethod
}

// home ログイン後のホーム画面を表示する (要認証)
func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFrom(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	data := homeData{Email: claims.Email, Sub: claims.Sub}
	// アプリDB未登録でもセッション自体は有効なため、認証方式一覧なしで表示を続行する
	_, methods, err := h.repo.FindBySub(r.Context(), claims.Sub)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		h.logger.Error("認証方式の取得に失敗しました", "error", err)
	}
	data.Methods = methods
	h.renderPage(w, "home", data)
}
