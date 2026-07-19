package cognito

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// ComputeSecretHash Cognitoのクライアントシークレット検証用ハッシュを計算する。
// 仕様上 username + clientID を連結した文字列を clientSecret でHMAC-SHA256し、
// base64標準エンコードした値をSecretHashパラメータとして送る
func ComputeSecretHash(username, clientID, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
