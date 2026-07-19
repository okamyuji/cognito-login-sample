package handler

import (
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/okamyuji/cognito-login-sample/internal/cognito"
	"github.com/okamyuji/cognito-login-sample/internal/repository"
)

// sessionCookieName セッション確立に使うIDトークンのCookie名
const sessionCookieName = "id_token"

// genericLoginFailure 認証失敗時の共通メッセージ。
// ユーザーの存在有無を区別しない文言によりアカウント列挙を防ぐ
const genericLoginFailure = "メールアドレスまたはパスワードが正しくありません。"

// validEmail メールアドレス形式の妥当性を検証する
func validEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email
}

// login メール+パスワードによるログインを処理する。
// Cognitoへ問い合わせる前にアプリDBの認証方式リンクを確認し、
// Google連携のみのアカウントにはパスワード経路を案内で遮断する
// (home realm discoveryの実演)
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	if !validEmail(email) || password == "" {
		h.renderFlash(w, "error", "メールアドレスとパスワードを入力してください。")
		return
	}

	// 認証方式リンクの確認。パスワード認証情報を持たないGoogle連携のみの
	// アカウントに対しては、Cognitoへ問い合わせずに正しい経路を案内する
	_, methods, err := h.repo.FindByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		h.logger.Error("認証方式の確認に失敗しました", "error", err)
		h.renderFlash(w, "error", "一時的なエラーが発生しました。しばらく待ってからやり直してください。")
		return
	}
	if err == nil && !hasMethod(methods, repository.MethodPassword) && hasMethod(methods, repository.MethodGoogle) {
		h.renderFlash(w, "info", "このアカウントはGoogleログインで作成されています。パスワードは設定されていないため、Googleでログインしてください。")
		return
	}

	result, err := h.cognito.InitiateAuth(r.Context(), email, password)
	if err != nil {
		switch {
		case errors.Is(err, cognito.ErrUserNotConfirmed):
			h.renderPage(w, "confirm_form", map[string]string{"Email": email})
		case errors.Is(err, cognito.ErrNotAuthorized), errors.Is(err, cognito.ErrUserNotFound):
			h.renderFlash(w, "error", genericLoginFailure)
		case errors.Is(err, cognito.ErrLimitExceeded):
			h.renderFlash(w, "error", "試行回数が上限を超えました。しばらく待ってからやり直してください。")
		default:
			h.logger.Error("ログインに失敗しました", "error", err)
			h.renderFlash(w, "error", "一時的なエラーが発生しました。しばらく待ってからやり直してください。")
		}
		return
	}

	// Cognitoが発行したIDトークンを自前で検証してからセッションを確立する
	claims, err := h.verifier.Verify(r.Context(), result.IDToken)
	if err != nil {
		h.logger.Error("IDトークンの検証に失敗しました", "error", err)
		h.renderFlash(w, "error", "一時的なエラーが発生しました。しばらく待ってからやり直してください。")
		return
	}

	// アプリ側ユーザーと認証方式リンクを冪等に登録する
	if err := h.repo.UpsertUserWithMethod(r.Context(),
		repository.User{Sub: claims.Sub, Email: claims.Email},
		repository.AuthMethod{UserSub: claims.Sub, Method: repository.MethodPassword},
	); err != nil {
		h.logger.Error("ユーザーの登録に失敗しました", "error", err)
		h.renderFlash(w, "error", "一時的なエラーが発生しました。しばらく待ってからやり直してください。")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    result.IDToken,
		Path:     "/",
		MaxAge:   result.ExpiresIn,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}

// hasMethod 認証方式一覧に指定方式が含まれるかどうかを判定する
func hasMethod(methods []repository.AuthMethod, method string) bool {
	for _, m := range methods {
		if m.Method == method {
			return true
		}
	}
	return false
}

// signup メール+パスワードによる仮登録を処理する
func (h *Handler) signup(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	if !validEmail(email) || password == "" {
		h.renderFlash(w, "error", "メールアドレスとパスワードを入力してください。")
		return
	}
	if err := h.cognito.SignUp(r.Context(), email, password); err != nil {
		switch {
		case errors.Is(err, cognito.ErrUsernameExists):
			// 登録済みかどうかを断定しない文言によりアカウント列挙を防ぐ
			h.renderFlash(w, "error", "登録を受け付けられませんでした。既に登録済みの場合はログインしてください。")
		case errors.Is(err, cognito.ErrInvalidPassword):
			h.renderFlash(w, "error", "パスワードは8文字以上で、英大文字・英小文字・数字を含めてください。")
		default:
			h.logger.Error("仮登録に失敗しました", "error", err)
			h.renderFlash(w, "error", "一時的なエラーが発生しました。しばらく待ってからやり直してください。")
		}
		return
	}
	h.renderPage(w, "confirm_form", map[string]string{"Email": email})
}

// confirm 確認コードによる本登録を処理する
func (h *Handler) confirm(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))
	if !validEmail(email) || code == "" {
		h.renderFlash(w, "error", "確認コードを入力してください。")
		return
	}
	if err := h.cognito.ConfirmSignUp(r.Context(), email, code); err != nil {
		switch {
		case errors.Is(err, cognito.ErrCodeMismatch):
			h.renderFlash(w, "error", "確認コードが一致しません。")
		case errors.Is(err, cognito.ErrExpiredCode):
			h.renderFlash(w, "error", "確認コードの期限が切れています。もう一度登録してください。")
		default:
			h.logger.Error("本登録に失敗しました", "error", err)
			h.renderFlash(w, "error", "一時的なエラーが発生しました。しばらく待ってからやり直してください。")
		}
		return
	}
	h.renderFlash(w, "success", "登録が完了しました。ログインしてください。")
}

// logout セッションCookieを破棄してログイン画面へ誘導する
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("HX-Redirect", "/login")
	w.WriteHeader(http.StatusOK)
}
