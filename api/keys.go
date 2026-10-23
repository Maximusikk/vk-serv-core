package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Key — запись таблицы keys.
type Key struct {
	ID           string
	CreatedAt    int64
	ActivatedAt  int64 // 0 = не активирован
	ExpiresAt    int64
	BytesLimit   int64 // 0 = безлимит
	BytesUsed    int64
	Port         int // 0 = не выделен
	UserToken    string
	WrapPassword string
	Notes        string
}

// Activated возвращает true, если ключ уже активирован.
func (k *Key) Activated() bool { return k.ActivatedAt > 0 }

// Expired возвращает true, если срок действия истёк.
func (k *Key) Expired() bool { return k.ExpiresAt > 0 && k.ExpiresAt <= nowUnix() }

// OverLimit возвращает true, если трафик исчерпан (для лимитированных ключей).
func (k *Key) OverLimit() bool { return k.BytesLimit > 0 && k.BytesUsed >= k.BytesLimit }

// GenerateKey возвращает ключ формата XXXX-XXXX-XXXX-XXXX из 8 случайных байт.
func GenerateKey() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := hex.EncodeToString(b) // 16 hex-символов
	return fmt.Sprintf("%s-%s-%s-%s", s[0:4], s[4:8], s[8:12], s[12:16]), nil
}

// GenerateHex возвращает случайный hex из n байт (для wrap_password).
func GenerateHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateUUID возвращает UUID v4.
func GenerateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // версия 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	s := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]), nil
}
