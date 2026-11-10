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

// cmdlineContains: вне Linux /proc недоступен — считаем процесс живым, если
// найден. Реальная реализация в kill_linux.go (используется reconcile.go для
// проверки direct-exec процессов).
func cmdlineContains(pid int, _ string) bool {
	_, err := os.FindProcess(pid)
	return err == nil
}
