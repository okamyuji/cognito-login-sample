// Package main Cognito認証サンプルのHTTPサーバを起動する
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/okamyuji/cognito-login-sample/internal/cognito"
	"github.com/okamyuji/cognito-login-sample/internal/config"
	"github.com/okamyuji/cognito-login-sample/internal/handler"
	"github.com/okamyuji/cognito-login-sample/internal/repository"
	"github.com/okamyuji/cognito-login-sample/internal/token"
	"github.com/okamyuji/cognito-login-sample/internal/web"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("サーバの起動に失敗しました", "error", err)
		os.Exit(1)
	}
}

// run 設定読み込みから依存の組み立て、サーバの起動と停止までを担う
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	db, err := sql.Open("mysql", cfg.MySQLDSN)
	if err != nil {
		return fmt.Errorf("MySQLへの接続設定に失敗しました: %w", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			logger.Error("MySQL接続のクローズに失敗しました", "error", cerr)
		}
	}()
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("MySQLへの接続確認に失敗しました: %w", err)
	}

	cognitoClient := cognito.NewHTTPClient(cfg.AWSRegion, cfg.ClientID, cfg.ClientSecret)
	verifier := token.NewJWKSVerifier(cfg.AWSRegion, cfg.UserPoolID, cfg.ClientID)
	repo := repository.NewMySQLUserRepository(db)

	h, err := handler.New(cognitoClient, repo, verifier, logger, cfg.CookieSecure)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           h.Routes(web.StaticFS()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("サーバを起動します", "addr", cfg.Addr)
		errCh <- server.ListenAndServe()
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-sigCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("サーバの停止に失敗しました: %w", err)
		}
		logger.Info("サーバを停止しました")
		return nil
	}
}
