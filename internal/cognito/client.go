// Package cognito AWS Cognitoユーザープールに対する認証操作を提供する
package cognito

import (
	"context"
	"errors"
)

// 認証操作で発生しうる代表的なエラー。ハンドラ層でユーザー向けメッセージへ変換する
var (
	// ErrNotAuthorized 認証情報の不一致を表すエラー
	ErrNotAuthorized = errors.New("cognito: 認証情報が一致しません")
	// ErrUserNotFound ユーザーが存在しないことを表すエラー
	ErrUserNotFound = errors.New("cognito: ユーザーが存在しません")
	// ErrUserNotConfirmed メールアドレスの確認が未完了であることを表すエラー
	ErrUserNotConfirmed = errors.New("cognito: ユーザーが未確認です")
	// ErrUsernameExists 同一ユーザー名の登録済みを表すエラー
	ErrUsernameExists = errors.New("cognito: ユーザーが既に存在します")
	// ErrInvalidPassword パスワードポリシー違反を表すエラー
	ErrInvalidPassword = errors.New("cognito: パスワードがポリシーを満たしません")
	// ErrCodeMismatch 確認コードの不一致を表すエラー
	ErrCodeMismatch = errors.New("cognito: 確認コードが一致しません")
	// ErrExpiredCode 確認コードの期限切れを表すエラー
	ErrExpiredCode = errors.New("cognito: 確認コードの期限が切れています")
	// ErrLimitExceeded 試行回数の上限超過を表すエラー
	ErrLimitExceeded = errors.New("cognito: 試行回数の上限を超えました")
)

// AuthResult InitiateAuth成功時にCognitoが返すトークン一式
type AuthResult struct {
	// IDToken ユーザー属性を含むJWT。本アプリのセッション確立に使う
	IDToken string
	// AccessToken Cognito API呼び出し用のJWT
	AccessToken string
	// RefreshToken トークン再発行用の資格情報
	RefreshToken string
	// ExpiresIn アクセストークンの有効秒数
	ExpiresIn int
}

// Client Cognitoユーザープールへの認証操作を抽象化するインターフェース。
// ハンドラ層がこのインターフェースにのみ依存することで、テストでは偽実装へ差し替えられる
type Client interface {
	// SignUp メールアドレスとパスワードでユーザーを仮登録する
	SignUp(ctx context.Context, email, password string) error
	// ConfirmSignUp メールで届いた確認コードにより仮登録を本登録へ昇格する
	ConfirmSignUp(ctx context.Context, email, code string) error
	// InitiateAuth USER_PASSWORD_AUTHフローで認証しトークン一式を得る
	InitiateAuth(ctx context.Context, email, password string) (*AuthResult, error)
}
