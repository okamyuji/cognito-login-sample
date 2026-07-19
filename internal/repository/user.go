// Package repository アプリ側ユーザーと認証方式リンクの永続化を提供する
package repository

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound 対象レコードが存在しないことを表すエラー
var ErrNotFound = errors.New("repository: レコードが存在しません")

// 認証方式を表す定数。auth_methodsテーブルのmethodカラムに対応する
const (
	// MethodPassword Cognitoユーザープール内のパスワード認証
	MethodPassword = "password"
	// MethodGoogle Google federated IdP経由の認証
	MethodGoogle = "google"
)

// User アプリ側で保持するユーザープロフィール。
// 認証情報 (パスワードハッシュ) はCognitoが保持するため、ここには存在しない
type User struct {
	// Sub Cognitoが払い出す一意識別子。主キーとして使う
	Sub string
	// Email 検証済みメールアドレス
	Email string
	// CreatedAt 作成日時
	CreatedAt time.Time
}

// AuthMethod ユーザーに紐づく認証方式のリンク。
// 1ユーザーが複数の認証方式を持てる設計により、
// パスワードとGoogleの両方でログインできるアカウント統合を表現する
type AuthMethod struct {
	// UserSub 対象ユーザーのsub
	UserSub string
	// Method 認証方式 (password / google)
	Method string
	// ProviderSub 外部IdP側のユーザー識別子。パスワード認証では空になる
	ProviderSub string
	// CreatedAt リンク作成日時
	CreatedAt time.Time
}

// UserRepository ユーザーと認証方式リンクの永続化を抽象化するインターフェース。
// ハンドラ層がこのインターフェースにのみ依存することで、テストでは偽実装へ差し替えられる
type UserRepository interface {
	// UpsertUserWithMethod ユーザーを登録または更新し、認証方式リンクを冪等に追加する
	UpsertUserWithMethod(ctx context.Context, user User, method AuthMethod) error
	// FindByEmail メールアドレスからユーザーと認証方式一覧を取得する。
	// 未登録の場合はErrNotFoundを返す
	FindByEmail(ctx context.Context, email string) (*User, []AuthMethod, error)
	// FindBySub subからユーザーと認証方式一覧を取得する。
	// 未登録の場合はErrNotFoundを返す
	FindBySub(ctx context.Context, sub string) (*User, []AuthMethod, error)
}
