package handler

import (
	"testing"
	"time"
)

// TestRateLimiterBlocksOverLimit 上限を超えたリクエストが拒否されることを検証する
func TestRateLimiterBlocksOverLimit(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	l := newRateLimiter(3, 60)
	l.now = func() time.Time { return now }

	for i := 1; i <= 3; i++ {
		if !l.allow("10.0.0.1") {
			t.Errorf("%d回目のリクエストが拒否されました (上限3回)", i)
		}
	}
	if l.allow("10.0.0.1") {
		t.Error("4回目のリクエストが許可されました (上限3回)")
	}
}

// TestRateLimiterIsolatesKeys 別IPのリクエストが他IPの消費量に影響されないことを検証する
func TestRateLimiterIsolatesKeys(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	l := newRateLimiter(1, 60)
	l.now = func() time.Time { return now }

	if !l.allow("10.0.0.1") {
		t.Error("10.0.0.1の1回目が拒否されました")
	}
	if l.allow("10.0.0.1") {
		t.Error("10.0.0.1の2回目が許可されました")
	}
	if !l.allow("10.0.0.2") {
		t.Error("別IP (10.0.0.2) の1回目が拒否されました")
	}
}

// TestRateLimiterResetsAfterWindow ウィンドウ経過後にカウントがリセットされることを検証する
func TestRateLimiterResetsAfterWindow(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	l := newRateLimiter(1, 60)
	l.now = func() time.Time { return now }

	if !l.allow("10.0.0.1") {
		t.Error("1回目が拒否されました")
	}
	if l.allow("10.0.0.1") {
		t.Error("ウィンドウ内の2回目が許可されました")
	}

	// ウィンドウ (60秒) を超えて時刻を進める
	now = now.Add(61 * time.Second)
	if !l.allow("10.0.0.1") {
		t.Error("ウィンドウ経過後のリクエストが拒否されました")
	}
}
