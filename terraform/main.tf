# cognito-login-sample 用のCognitoユーザープール定義。
# ユーザープールがローカルIdPとしてパスワードハッシュを保持し、
# アプリ側MySQLには認証情報を一切持たせない構成を実現する

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_cognito_user_pool" "this" {
  name = "cognito-login-sample"

  # メールアドレスをユーザー名として使い、確認コードで検証する
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # サンプル用途のため削除保護は無効にする
  deletion_protection = "INACTIVE"
}

resource "aws_cognito_user_pool_client" "server" {
  name         = "server"
  user_pool_id = aws_cognito_user_pool.this.id

  # サーバサイドで完結する構成のためクライアントシークレットを発行する
  generate_secret = true

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  # ユーザー不存在時にもNotAuthorizedExceptionを返させ、
  # レスポンス差分によるアカウント列挙を防ぐ
  prevent_user_existence_errors = "ENABLED"

  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
}
