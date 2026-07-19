// Package web 静的アセット (htmx / alpine.js / CSS) の埋め込みを提供する
package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFS embed.FS

// StaticFS 埋め込み済み静的アセットのファイルシステムを返す
func StaticFS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// embedの構成不備はビルド成果物の欠陥であり実行時に回復できないためpanicする
		panic(err)
	}
	return sub
}
