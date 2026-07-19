// Package token CognitoのIDトークン (JWT) を標準ライブラリのみで検証する機能を提供する
package token

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 検証で発生しうる代表的なエラー
var (
	// ErrInvalidToken トークンの形式または署名の不正を表すエラー
	ErrInvalidToken = errors.New("token: トークンが不正です")
	// ErrExpired トークンの期限切れを表すエラー
	ErrExpired = errors.New("token: トークンの期限が切れています")
)

// Claims 検証済みIDトークンから取り出す本アプリで使用するクレーム
type Claims struct {
	// Sub Cognitoが払い出すユーザーの一意識別子
	Sub string `json:"sub"`
	// Email ユーザーのメールアドレス
	Email string `json:"email"`
	// Issuer トークン発行者
	Issuer string `json:"iss"`
	// Audience トークンの想定利用者 (アプリクライアントID)
	Audience string `json:"aud"`
	// TokenUse トークン種別 (id / access)
	TokenUse string `json:"token_use"`
	// ExpiresAt 有効期限のUNIX秒
	ExpiresAt int64 `json:"exp"`
}

// Verifier IDトークンの検証を抽象化するインターフェース。
// ハンドラ層がこのインターフェースにのみ依存することで、テストでは偽実装へ差し替えられる
type Verifier interface {
	// Verify 署名とクレームを検証し、正当な場合のみクレームを返す
	Verify(ctx context.Context, rawToken string) (*Claims, error)
}

// jwk JWKSに含まれる単一のRSA公開鍵表現
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSVerifier CognitoのJWKSエンドポイントから公開鍵を取得して検証する実装
type JWKSVerifier struct {
	issuer   string
	audience string
	jwksURL  string
	httpc    *http.Client
	now      func() time.Time

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

// NewJWKSVerifier リージョン・ユーザープールID・クライアントIDから検証器を生成する
func NewJWKSVerifier(region, userPoolID, clientID string) *JWKSVerifier {
	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)
	return &JWKSVerifier{
		issuer:   issuer,
		audience: clientID,
		jwksURL:  issuer + "/.well-known/jwks.json",
		httpc:    &http.Client{Timeout: 10 * time.Second},
		now:      time.Now,
		keys:     map[string]*rsa.PublicKey{},
	}
}

// NewJWKSVerifierForTest テスト用に発行者・JWKS URL・現在時刻関数を直接指定して生成する
func NewJWKSVerifierForTest(issuer, audience, jwksURL string, now func() time.Time) *JWKSVerifier {
	return &JWKSVerifier{
		issuer:   issuer,
		audience: audience,
		jwksURL:  jwksURL,
		httpc:    &http.Client{Timeout: 10 * time.Second},
		now:      now,
		keys:     map[string]*rsa.PublicKey{},
	}
}

// Verify 署名とクレームを検証し、正当な場合のみクレームを返す
func (v *JWKSVerifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: 区切りの数が不正です", ErrInvalidToken)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: ヘッダの復号に失敗しました", ErrInvalidToken)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: ヘッダの解釈に失敗しました", ErrInvalidToken)
	}
	// alg=none等の署名なしトークンによるバイパスを遮断するためRS256のみ許可する
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("%w: 許可されないalgです (%s)", ErrInvalidToken, header.Alg)
	}

	pub, err := v.publicKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: 署名の復号に失敗しました", ErrInvalidToken)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("%w: 署名の検証に失敗しました", ErrInvalidToken)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: ペイロードの復号に失敗しました", ErrInvalidToken)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: クレームの解釈に失敗しました", ErrInvalidToken)
	}
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("%w: 発行者が一致しません", ErrInvalidToken)
	}
	if claims.Audience != v.audience {
		return nil, fmt.Errorf("%w: audが一致しません", ErrInvalidToken)
	}
	if claims.TokenUse != "id" {
		return nil, fmt.Errorf("%w: IDトークンではありません (token_use=%s)", ErrInvalidToken, claims.TokenUse)
	}
	if v.now().Unix() >= claims.ExpiresAt {
		return nil, ErrExpired
	}
	return &claims, nil
}

// publicKey kidに対応するRSA公開鍵をキャッシュまたはJWKSから取得する。
// 鍵ローテーションで未知のkidが来た場合は一度だけ再取得を試みる
func (v *JWKSVerifier) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	pub, ok := v.keys[kid]
	v.mu.RUnlock()
	if ok {
		return pub, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	pub, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: kidに対応する公開鍵がありません", ErrInvalidToken)
	}
	return pub, nil
}

// refresh JWKSエンドポイントから鍵一覧を取得しキャッシュを置き換える
func (v *JWKSVerifier) refresh(ctx context.Context) (err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("token: JWKSリクエストの生成に失敗しました: %w", err)
	}
	resp, err := v.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("token: JWKSの取得に失敗しました: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("token: JWKSレスポンスのクローズに失敗しました: %w", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token: JWKSの取得に失敗しました (status=%d)", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("token: JWKSの読み取りに失敗しました: %w", err)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("token: JWKSの解釈に失敗しました: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, perr := jwkToPublicKey(k)
		if perr != nil {
			return perr
		}
		keys[k.Kid] = pub
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

// jwkToPublicKey JWKのn/eフィールドをrsa.PublicKeyへ変換する
func jwkToPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("token: JWKのnの復号に失敗しました: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("token: JWKのeの復号に失敗しました: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 1 {
		return nil, fmt.Errorf("token: JWKのeが不正です")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
