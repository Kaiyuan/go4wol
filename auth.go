package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var adminPassword string

// 注意：在实际生产中，Secret 应该更加随机且持久化。
// 这里我们使用 adminPassword 加上一个固定的盐值作为签名密钥，
// 这样只要管理员密码不变，重启服务后之前的 Token 依然有效。
func getJWTSecret() []byte {
	return []byte(adminPassword + "go4wol-secret-salt")
}

// GenerateToken 生成一个简易的 JWT 令牌
func GenerateToken(password string) (string, error) {
	if password != adminPassword {
		return "", fmt.Errorf("invalid password")
	}

	// Header
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	// Payload
	payloadMap := map[string]interface{}{
		"authorized": true,
		"exp":        time.Now().Add(time.Hour * 24 * 7).Unix(), // 7天过期
		"iat":        time.Now().Unix(),
	}
	payloadBytes, _ := json.Marshal(payloadMap)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Signature
	unsignedToken := header + "." + payload
	h := hmac.New(sha256.New, getJWTSecret())
	h.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return unsignedToken + "." + signature, nil
}

// ValidateToken 验证 JWT 令牌
func ValidateToken(tokenString string) bool {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}

	headerPayload := parts[0] + "." + parts[1]
	signature := parts[2]

	// 重新计算签名
	h := hmac.New(sha256.New, getJWTSecret())
	h.Write([]byte(headerPayload))
	expectedSignature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if signature != expectedSignature {
		return false
	}

	// 验证过期时间
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		return false
	}

	if time.Now().Unix() > int64(exp) {
		return false
	}

	return true
}

// authMiddleware 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" || !strings.HasPrefix(token, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			return
		}

		actualToken := strings.TrimPrefix(token, "Bearer ")
		if !ValidateToken(actualToken) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			return
		}
		next(w, r)
	}
}
