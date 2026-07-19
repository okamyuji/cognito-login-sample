output "user_pool_id" {
  description = "CognitoユーザープールのID"
  value       = aws_cognito_user_pool.this.id
}

output "client_id" {
  description = "アプリクライアントのID"
  value       = aws_cognito_user_pool_client.server.id
}

output "client_secret" {
  description = "アプリクライアントのシークレット"
  value       = aws_cognito_user_pool_client.server.client_secret
  sensitive   = true
}
