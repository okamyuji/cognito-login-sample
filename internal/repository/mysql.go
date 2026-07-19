package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// MySQLUserRepository UserRepositoryのMySQL実装
type MySQLUserRepository struct {
	db *sql.DB
}

// NewMySQLUserRepository 接続済みの*sql.DBからリポジトリを生成する
func NewMySQLUserRepository(db *sql.DB) *MySQLUserRepository {
	return &MySQLUserRepository{db: db}
}

// UpsertUserWithMethod ユーザーを登録または更新し、認証方式リンクを冪等に追加する。
// 2つの書き込みを1トランザクションで行い、部分的な登録状態を残さない
func (r *MySQLUserRepository) UpsertUserWithMethod(ctx context.Context, user User, method AuthMethod) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("repository: トランザクションの開始に失敗しました: %w", err)
	}
	defer func() {
		if err != nil {
			if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("repository: ロールバックに失敗しました: %w", rerr))
			}
		}
	}()

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO users (sub, email) VALUES (?, ?)
		 ON DUPLICATE KEY UPDATE email = VALUES(email)`,
		user.Sub, user.Email,
	); err != nil {
		return fmt.Errorf("repository: ユーザーの登録に失敗しました: %w", err)
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO auth_methods (user_sub, method, provider_sub) VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE provider_sub = VALUES(provider_sub)`,
		method.UserSub, method.Method, method.ProviderSub,
	); err != nil {
		return fmt.Errorf("repository: 認証方式リンクの登録に失敗しました: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("repository: コミットに失敗しました: %w", err)
	}
	return nil
}

// FindByEmail メールアドレスからユーザーと認証方式一覧を取得する
func (r *MySQLUserRepository) FindByEmail(ctx context.Context, email string) (*User, []AuthMethod, error) {
	return r.findWhere(ctx, "email = ?", email)
}

// FindBySub subからユーザーと認証方式一覧を取得する
func (r *MySQLUserRepository) FindBySub(ctx context.Context, sub string) (*User, []AuthMethod, error) {
	return r.findWhere(ctx, "sub = ?", sub)
}

// findWhere 条件句を指定してユーザー1件と認証方式一覧を取得する
func (r *MySQLUserRepository) findWhere(ctx context.Context, cond string, arg any) (*User, []AuthMethod, error) {
	var u User
	row := r.db.QueryRowContext(ctx,
		`SELECT sub, email, created_at FROM users WHERE `+cond, arg)
	if err := row.Scan(&u.Sub, &u.Email, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("repository: ユーザーの取得に失敗しました: %w", err)
	}

	methods, err := r.findMethods(ctx, u.Sub)
	if err != nil {
		return nil, nil, err
	}
	return &u, methods, nil
}

// findMethods 指定ユーザーの認証方式一覧を取得する
func (r *MySQLUserRepository) findMethods(ctx context.Context, sub string) (methods []AuthMethod, err error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT user_sub, method, provider_sub, created_at
		 FROM auth_methods WHERE user_sub = ? ORDER BY method`, sub)
	if err != nil {
		return nil, fmt.Errorf("repository: 認証方式の取得に失敗しました: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("repository: 行のクローズに失敗しました: %w", cerr)
		}
	}()
	for rows.Next() {
		var m AuthMethod
		if err := rows.Scan(&m.UserSub, &m.Method, &m.ProviderSub, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("repository: 認証方式の読み取りに失敗しました: %w", err)
		}
		methods = append(methods, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repository: 認証方式の走査に失敗しました: %w", err)
	}
	return methods, nil
}
