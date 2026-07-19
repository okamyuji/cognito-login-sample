package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"
)

// testDB テストスイート全体で共有するMySQL接続。
// sqlmockではなくtestcontainersの実MySQLに対してSQLを実行することで、
// スキーマ・制約・型との乖離をCIの段階で検出する
var testDB *sql.DB

// TestMain MySQLコンテナを1回だけ起動し、全テストで共有する
func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "テスト環境の構築に失敗しました: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runMain コンテナの起動から後始末までを担い、テストの終了コードを返す
func runMain(m *testing.M) (int, error) {
	ctx := context.Background()
	ctr, err := tcmysql.Run(ctx, "mysql:8.4",
		tcmysql.WithDatabase("testdb"),
		tcmysql.WithUsername("testuser"),
		tcmysql.WithPassword("testpass"),
		tcmysql.WithScripts(filepath.Join("..", "..", "db", "schema.sql")),
	)
	if err != nil {
		return 0, fmt.Errorf("MySQLコンテナの起動に失敗しました: %w", err)
	}
	defer func() {
		if terr := ctr.Terminate(ctx); terr != nil {
			fmt.Fprintf(os.Stderr, "コンテナの停止に失敗しました: %v\n", terr)
		}
	}()

	dsn, err := ctr.ConnectionString(ctx, "parseTime=true")
	if err != nil {
		return 0, fmt.Errorf("接続文字列の取得に失敗しました: %w", err)
	}
	testDB, err = sql.Open("mysql", dsn)
	if err != nil {
		return 0, fmt.Errorf("MySQLへの接続に失敗しました: %w", err)
	}
	defer func() {
		if cerr := testDB.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "接続のクローズに失敗しました: %v\n", cerr)
		}
	}()
	if err := testDB.PingContext(ctx); err != nil {
		return 0, fmt.Errorf("MySQLへの疎通確認に失敗しました: %w", err)
	}
	return m.Run(), nil
}

// truncateAll テスト間の独立性を保つため全テーブルを空にする
func truncateAll(t *testing.T) {
	t.Helper()
	for _, table := range []string{"auth_methods", "users"} {
		if _, err := testDB.Exec("DELETE FROM " + table); err != nil {
			t.Fatalf("%sの初期化に失敗しました: %v", table, err)
		}
	}
}

// TestUpsertUserWithMethodInsertsRow 新規ユーザーの登録でDB上に期待どおりの行が作られることを検証する
func TestUpsertUserWithMethodInsertsRow(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)
	ctx := context.Background()

	err := repo.UpsertUserWithMethod(ctx,
		User{Sub: "sub-0001", Email: "user@example.com"},
		AuthMethod{UserSub: "sub-0001", Method: MethodPassword},
	)
	if err != nil {
		t.Fatalf("UpsertUserWithMethod() error = %v", err)
	}

	// DB上の実際の行を読み戻し、保存された値そのものを検証する
	user, methods, err := repo.FindBySub(ctx, "sub-0001")
	if err != nil {
		t.Fatalf("FindBySub() error = %v", err)
	}
	if user.Sub != "sub-0001" {
		t.Errorf("Sub = %q, want %q", user.Sub, "sub-0001")
	}
	if user.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "user@example.com")
	}
	if user.CreatedAt.IsZero() {
		t.Error("CreatedAtが設定されていません")
	}
	if len(methods) != 1 {
		t.Fatalf("認証方式の件数 = %d, want 1", len(methods))
	}
	if methods[0].Method != MethodPassword {
		t.Errorf("Method = %q, want %q", methods[0].Method, MethodPassword)
	}
	if methods[0].ProviderSub != "" {
		t.Errorf("ProviderSub = %q, want 空", methods[0].ProviderSub)
	}
}

// TestUpsertUserWithMethodIsIdempotent 同じ登録を繰り返しても行が増えないことを検証する。
// ログインのたびに呼ばれる操作のため冪等性が必須になる
func TestUpsertUserWithMethodIsIdempotent(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)
	ctx := context.Background()

	for range 3 {
		err := repo.UpsertUserWithMethod(ctx,
			User{Sub: "sub-0001", Email: "user@example.com"},
			AuthMethod{UserSub: "sub-0001", Method: MethodPassword},
		)
		if err != nil {
			t.Fatalf("UpsertUserWithMethod() error = %v", err)
		}
	}

	var userCount, methodCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		t.Fatalf("usersの件数取得に失敗しました: %v", err)
	}
	if err := testDB.QueryRow("SELECT COUNT(*) FROM auth_methods").Scan(&methodCount); err != nil {
		t.Fatalf("auth_methodsの件数取得に失敗しました: %v", err)
	}
	if userCount != 1 {
		t.Errorf("usersの件数 = %d, want 1", userCount)
	}
	if methodCount != 1 {
		t.Errorf("auth_methodsの件数 = %d, want 1", methodCount)
	}
}

// TestUpsertAddsSecondMethod 同一ユーザーへの別方式の追加で1アカウント2方式になることを検証する。
// パスワードとGoogleを併存させるアカウント統合のデータモデルを実DBで確かめる
func TestUpsertAddsSecondMethod(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)
	ctx := context.Background()

	if err := repo.UpsertUserWithMethod(ctx,
		User{Sub: "sub-0001", Email: "user@example.com"},
		AuthMethod{UserSub: "sub-0001", Method: MethodPassword},
	); err != nil {
		t.Fatalf("password方式の登録に失敗しました: %v", err)
	}
	if err := repo.UpsertUserWithMethod(ctx,
		User{Sub: "sub-0001", Email: "user@example.com"},
		AuthMethod{UserSub: "sub-0001", Method: MethodGoogle, ProviderSub: "google-oauth2|111"},
	); err != nil {
		t.Fatalf("google方式の登録に失敗しました: %v", err)
	}

	_, methods, err := repo.FindByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("認証方式の件数 = %d, want 2", len(methods))
	}
	// ORDER BY methodによりgoogle, passwordの順で返る
	if methods[0].Method != MethodGoogle || methods[0].ProviderSub != "google-oauth2|111" {
		t.Errorf("methods[0] = %+v, want google / google-oauth2|111", methods[0])
	}
	if methods[1].Method != MethodPassword {
		t.Errorf("methods[1] = %+v, want password", methods[1])
	}
}

// TestFindByEmailNotFound 未登録メールでErrNotFoundが返ることを検証する
func TestFindByEmailNotFound(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)

	_, _, err := repo.FindByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByEmail() error = %v, want ErrNotFound", err)
	}
}

// TestFindBySubNotFound 未登録subでErrNotFoundが返ることを検証する
func TestFindBySubNotFound(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)

	_, _, err := repo.FindBySub(context.Background(), "no-such-sub")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("FindBySub() error = %v, want ErrNotFound", err)
	}
}

// TestEmailUniqueConstraint 同一メールで異なるsubの登録がスキーマ制約で拒否されることを検証する。
// アプリのバグで別アカウントが同一メールを奪えないことをDB層の制約として保証する
func TestEmailUniqueConstraint(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)
	ctx := context.Background()

	if err := repo.UpsertUserWithMethod(ctx,
		User{Sub: "sub-0001", Email: "user@example.com"},
		AuthMethod{UserSub: "sub-0001", Method: MethodPassword},
	); err != nil {
		t.Fatalf("1件目の登録に失敗しました: %v", err)
	}
	err := repo.UpsertUserWithMethod(ctx,
		User{Sub: "sub-9999", Email: "user@example.com"},
		AuthMethod{UserSub: "sub-9999", Method: MethodPassword},
	)
	if err == nil {
		t.Fatal("同一メール・別subの登録が成功してしまいました")
	}
}

// TestUpsertRollsBackOnMethodFailure 認証方式の登録失敗時にユーザー登録もロールバックされることを検証する。
// 外部キー違反を意図的に起こし、部分的な登録状態が残らないことを実DBで確かめる
func TestUpsertRollsBackOnMethodFailure(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)
	ctx := context.Background()

	// user_subにusersへ存在しない値を渡し、auth_methods側の外部キー違反を誘発する
	err := repo.UpsertUserWithMethod(ctx,
		User{Sub: "sub-0001", Email: "user@example.com"},
		AuthMethod{UserSub: "different-sub", Method: MethodPassword},
	)
	if err == nil {
		t.Fatal("外部キー違反の登録が成功してしまいました")
	}

	var userCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		t.Fatalf("usersの件数取得に失敗しました: %v", err)
	}
	if userCount != 0 {
		t.Errorf("ロールバック後のusersの件数 = %d, want 0 (部分的な登録が残っています)", userCount)
	}
}

// TestTimestampsAreRecent 保存されたcreated_atが現在時刻に近いことを検証する。
// タイムゾーン設定の齟齬による大幅なずれを検出する
func TestTimestampsAreRecent(t *testing.T) {
	truncateAll(t)
	repo := NewMySQLUserRepository(testDB)
	ctx := context.Background()

	before := time.Now().Add(-5 * time.Minute)
	if err := repo.UpsertUserWithMethod(ctx,
		User{Sub: "sub-0001", Email: "user@example.com"},
		AuthMethod{UserSub: "sub-0001", Method: MethodPassword},
	); err != nil {
		t.Fatalf("登録に失敗しました: %v", err)
	}
	user, _, err := repo.FindBySub(ctx, "sub-0001")
	if err != nil {
		t.Fatalf("FindBySub() error = %v", err)
	}
	after := time.Now().Add(5 * time.Minute)
	if user.CreatedAt.Before(before) || user.CreatedAt.After(after) {
		t.Errorf("CreatedAt = %v, want %v〜%vの範囲", user.CreatedAt, before, after)
	}
}
