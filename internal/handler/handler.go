// Package handler HTTPハンドラとルーティングを提供する
package handler

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/okamyuji/cognito-login-sample/internal/cognito"
	"github.com/okamyuji/cognito-login-sample/internal/repository"
	"github.com/okamyuji/cognito-login-sample/internal/token"
)

//go:embed templates/*.html
var templateFS embed.FS

// Handler 依存をインターフェースとして受け取るHTTPハンドラ集約。
// cognito.Client / repository.UserRepository / token.Verifier のいずれも
// インターフェースであり、テストでは偽実装を注入する
type Handler struct {
	cognito      cognito.Client
	repo         repository.UserRepository
	verifier     token.Verifier
	tmpl         *template.Template
	logger       *slog.Logger
	cookieSecure bool
	limiter      *rateLimiter
}

// New 依存を注入してHandlerを生成する
func New(c cognito.Client, r repository.UserRepository, v token.Verifier, logger *slog.Logger, cookieSecure bool) (*Handler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("handler: テンプレートの読み込みに失敗しました: %w", err)
	}
	return &Handler{
		cognito:      c,
		repo:         r,
		verifier:     v,
		tmpl:         tmpl,
		logger:       logger,
		cookieSecure: cookieSecure,
		limiter:      newRateLimiter(20, 60), // 1分あたり20リクエストをIP単位で許可する
	}, nil
}

// Routes 全ルートを登録したhttp.Handlerを返す
func (h *Handler) Routes(staticFS fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	mux.HandleFunc("GET /login", h.loginPage)
	mux.HandleFunc("GET /signup", h.signupPage)
	mux.HandleFunc("POST /api/login", h.limiter.wrap(h.login))
	mux.HandleFunc("POST /api/signup", h.limiter.wrap(h.signup))
	mux.HandleFunc("POST /api/confirm", h.limiter.wrap(h.confirm))
	mux.HandleFunc("POST /api/logout", h.logout)
	mux.Handle("GET /{$}", h.requireAuth(http.HandlerFunc(h.home)))

	// クロスオリジンからの状態変更リクエストを遮断する (CSRF対策)。
	// Sec-Fetch-Site / Originヘッダに基づく標準ライブラリの保護を全体へ適用する
	csrf := http.NewCrossOriginProtection()
	return csrf.Handler(securityHeaders(mux))
}

// securityHeaders 全レスポンスへセキュリティ関連ヘッダを付与するミドルウェア
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Alpine.jsの標準ビルドが式評価にFunctionコンストラクタを使うため
		// script-srcに'unsafe-eval'を許可している。本番ではCSPビルドへの
		// 差し替えにより'unsafe-eval'を外すことを推奨する
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

// renderPage レイアウト付きのページ全体を描画する
func (h *Handler) renderPage(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.logger.Error("テンプレートの描画に失敗しました", "template", name, "error", err)
	}
}

// renderFlash htmxのターゲットへ差し込むメッセージ断片を描画する
func (h *Handler) renderFlash(w http.ResponseWriter, kind, message string) {
	h.renderPage(w, "flash", map[string]string{"Kind": kind, "Message": message})
}
