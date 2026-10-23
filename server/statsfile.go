// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// runStatsFile периодически пишет накопленный трафик порта в файл:
//
//	<start_unix> <rx_bytes> <tx_bytes>
//
// start_unix меняется при каждом перезапуске процесса — по нему читатель (vkturn-api)
// понимает, что счётчики начались с нуля. Запись атомарная (tmp + rename).
func runStatsFile(ctx context.Context, path string, every time.Duration) {
	start := time.Now().Unix()
	write := func() {
		data := fmt.Sprintf("%d %d %d\n", start, wireStats.rx.Load(), wireStats.tx.Load())
		tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
		if err := os.WriteFile(tmp, []byte(data), 0640); err != nil {
			log.Printf("stats-file: %v", err)
			return
		}
		if err := os.Rename(tmp, path); err != nil {
			log.Printf("stats-file: %v", err)
		}
	}
	write()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			write() // последние байты перед остановкой
			return
		case <-t.C:
			write()
		}
	}
}
