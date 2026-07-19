-- users アプリ側ユーザープロフィール。
-- 認証情報 (パスワードハッシュ) はCognitoユーザープールが保持するため、
-- このデータベースには一切保存しない
CREATE TABLE IF NOT EXISTS users (
    sub        VARCHAR(64)  NOT NULL COMMENT 'Cognitoが払い出す一意識別子',
    email      VARCHAR(255) NOT NULL COMMENT '検証済みメールアドレス',
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (sub),
    UNIQUE KEY uk_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- auth_methods ユーザーに紐づく認証方式リンク。
-- 1アカウント : N認証方式のモデルにより、パスワードとGoogleの
-- 両方でログインできるアカウント統合を表現する
CREATE TABLE IF NOT EXISTS auth_methods (
    id           BIGINT       NOT NULL AUTO_INCREMENT,
    user_sub     VARCHAR(64)  NOT NULL COMMENT '対象ユーザーのsub',
    method       VARCHAR(32)  NOT NULL COMMENT '認証方式 (password / google)',
    provider_sub VARCHAR(255) NOT NULL DEFAULT '' COMMENT '外部IdP側のユーザー識別子',
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_auth_methods_user_method (user_sub, method),
    CONSTRAINT fk_auth_methods_user FOREIGN KEY (user_sub) REFERENCES users (sub) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
