//go:build !linux

package main

import "os"

// killPortProcess: вне Linux (/proc недоступен) просто убиваем процесс по pid.
// Продакшен — Linux; ветка нужна, чтобы модуль собирался на других платформах.
func killPortProcess(pid int, _ string) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
