package cognito

import "testing"

// TestComputeSecretHash 既知ベクトルとの一致により計算式の正しさを固定する。
// 期待値はGo実装と独立にPython (hmac + hashlib) で算出した値を使い、
// 実装の写しがテストになることを避けている
func TestComputeSecretHash(t *testing.T) {
	tests := []struct {
		name     string
		username string
		clientID string
		secret   string
		want     string
	}{
		{
			name:     "既知ベクトルと一致する",
			username: "user@example.com",
			clientID: "test-client-id",
			secret:   "test-secret",
			want:     "xrsTnzy6gvX+NdflYLBNphr0QsoYNCUiyPGjN3Gpjng=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeSecretHash(tt.username, tt.clientID, tt.secret)
			if got != tt.want {
				t.Errorf("ComputeSecretHash() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestComputeSecretHashDiffers 入力の違いが必ず異なるハッシュを生むことを確認する。
// usernameとclientIDの連結順の取り違えを検出する
func TestComputeSecretHashDiffers(t *testing.T) {
	base := ComputeSecretHash("user@example.com", "client", "secret")
	swapped := ComputeSecretHash("client", "user@example.com", "secret")
	if base == swapped {
		t.Errorf("連結順を入れ替えても同一のハッシュになっています: %q", base)
	}
}
