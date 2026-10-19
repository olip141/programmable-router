package webui

import "embed"

//go:embed web/*
var staticFS embed.FS
