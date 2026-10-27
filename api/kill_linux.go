//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// killPortProcess завершает direct-exec процесс server (G3/Z-16).
// Защита от переиспользования pid: перед kill сверяем /proc/<pid>/cmdline
// с путём бинарника server — чужой процесс не трогаем. SIGTERM, затем
// SIGKILL, если процесс не завершился за 2 секунды.
func killPortProcess(pid int, serverPath string) {
	if !cmdlineContains(pid, serverPath) {
		return // процесс мёртв или это не наш server
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return // процесс завершён
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// cmdlineContains сообщает, жив ли процесс и упоминается ли serverPath в его cmdline.
func cmdlineContains(pid int, serverPath string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), serverPath)
}
