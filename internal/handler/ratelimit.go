package handler

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter IP単位の固定ウィンドウ方式による簡易レートリミッタ。
// 認証エンドポイントへの総当たり攻撃の速度を抑えることが目的で、
// 分散環境での厳密な制限が必要になった場合は外部ストアへの置き換えが必要になる
type rateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	limit   int
	window  time.Duration
	resetAt time.Time
	now     func() time.Time
}

// newRateLimiter 1ウィンドウあたりの許可回数とウィンドウ秒数からリミッタを生成する
func newRateLimiter(limit, windowSeconds int) *rateLimiter {
	return &rateLimiter{
		counts: map[string]int{},
		limit:  limit,
		window: time.Duration(windowSeconds) * time.Second,
		now:    time.Now,
	}
}

// allow 指定キーのリクエストを許可するかどうかを判定する
func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.After(l.resetAt) {
		l.counts = map[string]int{}
		l.resetAt = now.Add(l.window)
	}
	l.counts[key]++
	return l.counts[key] <= l.limit
}

// wrap ハンドラをレート制限付きでラップする
func (l *rateLimiter) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !l.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			if _, werr := w.Write([]byte(`<div class="flash error">リクエストが多すぎます。しばらく待ってからやり直してください。</div>`)); werr != nil {
				return
			}
			return
		}
		next(w, r)
	}
}
