package token

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedNow テストで使う固定の現在時刻
var fixedNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

const (
	testIssuer   = "https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_TESTPOOL"
	testAudience = "test-client-id"
)

// testKey テスト全体で使い回すRSA鍵。生成コストを1回に抑える
var testKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

// signJWT 指定ヘッダ・クレームのJWTをtestKeyで署名して生成する
func signJWT(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("ヘッダの生成に失敗しました: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("クレームの生成に失敗しました: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, testKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("署名に失敗しました: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// newJWKSServer testKeyの公開鍵をCognitoと同じJWKS形式で配信するサーバを起動する
func newJWKSServer(t *testing.T, kid string) *httptest.Server {
	t.Helper()
	pub := testKey.Public().(*rsa.PublicKey)
	jwks := map[string]any{
		"keys": []map[string]string{
			{
				"kid": kid,
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Errorf("JWKSの書き込みに失敗しました: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// validClaims 検証を通過する標準的なクレーム一式を返す
func validClaims() map[string]any {
	return map[string]any{
		"sub":       "sub-1234",
		"email":     "user@example.com",
		"iss":       testIssuer,
		"aud":       testAudience,
		"token_use": "id",
		"exp":       fixedNow.Add(1 * time.Hour).Unix(),
	}
}

// TestVerifyValidToken 正当なIDトークンからクレームの中身まで取り出せることを検証する
func TestVerifyValidToken(t *testing.T) {
	srv := newJWKSServer(t, "kid-1")
	v := NewJWKSVerifierForTest(testIssuer, testAudience, srv.URL, func() time.Time { return fixedNow })

	tok := signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, validClaims())
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Sub != "sub-1234" {
		t.Errorf("Sub = %q, want %q", claims.Sub, "sub-1234")
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "user@example.com")
	}
}

// TestVerifyRejects 不正なトークンをすべて拒否することをテーブル駆動で検証する。
// 有効期限・発行者・aud・token_use・署名アルゴリズムという
// 検証条件の組み合わせを1条件ずつ崩し、どの条件の欠落も検出されることを確かめる
func TestVerifyRejects(t *testing.T) {
	srv := newJWKSServer(t, "kid-1")
	newVerifier := func() *JWKSVerifier {
		return NewJWKSVerifierForTest(testIssuer, testAudience, srv.URL, func() time.Time { return fixedNow })
	}

	tests := []struct {
		name    string
		token   func(t *testing.T) string
		wantErr error
	}{
		{
			name: "期限切れのトークンを拒否する",
			token: func(t *testing.T) string {
				c := validClaims()
				c["exp"] = fixedNow.Add(-1 * time.Second).Unix()
				return signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, c)
			},
			wantErr: ErrExpired,
		},
		{
			name: "expちょうどの境界時刻を拒否する",
			token: func(t *testing.T) string {
				c := validClaims()
				c["exp"] = fixedNow.Unix()
				return signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, c)
			},
			wantErr: ErrExpired,
		},
		{
			name: "発行者の異なるトークンを拒否する",
			token: func(t *testing.T) string {
				c := validClaims()
				c["iss"] = "https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_OTHER"
				return signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, c)
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "audの異なるトークンを拒否する",
			token: func(t *testing.T) string {
				c := validClaims()
				c["aud"] = "other-client-id"
				return signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, c)
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "アクセストークン (token_use=access) を拒否する",
			token: func(t *testing.T) string {
				c := validClaims()
				c["token_use"] = "access"
				return signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, c)
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "alg=noneの署名なしトークンを拒否する",
			token: func(t *testing.T) string {
				headerJSON, _ := json.Marshal(map[string]any{"alg": "none"})
				claimsJSON, _ := json.Marshal(validClaims())
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(claimsJSON) + "."
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "ペイロード改ざんを署名検証で拒否する",
			token: func(t *testing.T) string {
				tok := signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, validClaims())
				// 署名後のペイロード部分だけを別ユーザーのクレームへ差し替える
				c := validClaims()
				c["sub"] = "attacker"
				forged, err := json.Marshal(c)
				if err != nil {
					t.Fatalf("改ざんクレームの生成に失敗しました: %v", err)
				}
				segs := strings.Split(tok, ".")
				return segs[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + segs[2]
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "JWKSに存在しないkidを拒否する",
			token: func(t *testing.T) string {
				return signJWT(t, map[string]any{"alg": "RS256", "kid": "unknown-kid"}, validClaims())
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "空文字列を拒否する",
			token: func(t *testing.T) string {
				return ""
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "区切りが2つしかない文字列を拒否する",
			token: func(t *testing.T) string {
				return "abc.def"
			},
			wantErr: ErrInvalidToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := newVerifier().Verify(context.Background(), tt.token(t))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Verify() error = %v, want errors.Is(err, %v)", err, tt.wantErr)
			}
			if claims != nil {
				t.Errorf("拒否時にクレームが返っています: %+v", claims)
			}
		})
	}
}

// TestVerifyConcurrent 複数goroutineからの同時検証でも安全に動作することを検証する。
// JWKSキャッシュの共有状態に対するデータレースを-race付きの実行で検出する
func TestVerifyConcurrent(t *testing.T) {
	srv := newJWKSServer(t, "kid-1")
	v := NewJWKSVerifierForTest(testIssuer, testAudience, srv.URL, func() time.Time { return fixedNow })
	tok := signJWT(t, map[string]any{"alg": "RS256", "kid": "kid-1"}, validClaims())

	var wg sync.WaitGroup
	errCh := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			claims, err := v.Verify(context.Background(), tok)
			if err != nil {
				errCh <- err
				return
			}
			if claims.Sub != "sub-1234" {
				errCh <- fmt.Errorf("Sub = %q, want sub-1234", claims.Sub)
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("並行検証でエラーが発生しました: %v", err)
	}
}
