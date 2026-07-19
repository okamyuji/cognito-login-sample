// Package config 環境変数からアプリケーション設定を読み込む機能を提供する
package config

import (
	"fmt"
	"os"
)

// Config アプリケーション全体の設定値を保持する構造体
type Config struct {
	// Addr HTTPサーバの待ち受けアドレス
	Addr string
	// AWSRegion CognitoユーザープールのAWSリージョン
	AWSRegion string
	// UserPoolID CognitoユーザープールのID
	UserPoolID string
	// ClientID Cognitoアプリクライアントのid
	ClientID string
	// ClientSecret Cognitoアプリクライアントのシークレット
	ClientSecret string
	// MySQLDSN MySQL接続文字列
	MySQLDSN string
	// CookieSecure CookieにSecure属性を付与するかどうか
	CookieSecure bool
}

// Load 環境変数から設定を読み込み、必須項目の欠落があればエラーを返す
func Load() (*Config, error) {
	cfg := &Config{
		Addr:         getenvDefault("ADDR", ":8080"),
		AWSRegion:    os.Getenv("AWS_REGION"),
		UserPoolID:   os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:     os.Getenv("COGNITO_CLIENT_ID"),
		ClientSecret: os.Getenv("COGNITO_CLIENT_SECRET"),
		MySQLDSN:     os.Getenv("MYSQL_DSN"),
		CookieSecure: os.Getenv("COOKIE_SECURE") == "true",
	}
	missing := []string{}
	if cfg.AWSRegion == "" {
		missing = append(missing, "AWS_REGION")
	}
	if cfg.UserPoolID == "" {
		missing = append(missing, "COGNITO_USER_POOL_ID")
	}
	if cfg.ClientID == "" {
		missing = append(missing, "COGNITO_CLIENT_ID")
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, "COGNITO_CLIENT_SECRET")
	}
	if cfg.MySQLDSN == "" {
		missing = append(missing, "MYSQL_DSN")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("必須環境変数が未設定です: %v", missing)
	}
	return cfg, nil
}

// getenvDefault 環境変数の値を返し、未設定の場合は既定値を返す
func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
