package back

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	jwtSecret     []byte
	jwtSecretPath = "jwt_secret.key"
	jwtMu         sync.Mutex
)

// 初始化JWT密钥
func InitJWTSecret() {
	if data, err := os.ReadFile(jwtSecretPath); err == nil && len(data) > 0 {
		jwtSecret = data
		return
	}
	fmt.Println("JWT密钥文件不存在或为空")
	os.Exit(1)
}

// 从请求头获取并校验JWT，返回username和role
func getNameAndRole(r *http.Request) (string, string, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", "", http.ErrNoCookie
	}
	tokenStr := strings.TrimPrefix(auth, "Bearer ")
	token, err := checkToken(tokenStr)
	if err != nil || !token.Valid {
		return "", "", http.ErrNoCookie
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", http.ErrNoCookie
	}
	role, _ := claims["role"].(string)
	username, _ := claims["username"].(string)
	return username, role, nil
}

// 探针端token生成
func generateTokenFroProbe(username, role, iface string) (string, error) {
	claims := jwt.MapClaims{
		"username":  username,
		"role":      role,
		"device_id": iface,
		"exp":       time.Now().Add(24 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// 平台端token生成
func generateTokenForPlatform(username, role string) (string, error) {
	claims := map[string]interface{}{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	return token.SignedString(jwtSecret)
}

// JWT校验
func checkToken(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
}

// JWT密钥重生成
func HandleAdminRegenerateJWTSecret(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST", http.StatusMethodNotAllowed)
		return
	}
	err = generateJWTSecret()
	if err != nil {
		http.Error(w, "密钥生成失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func generateJWTSecret() error {
	jwtMu.Lock()
	defer jwtMu.Unlock()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(secret)
	err = os.WriteFile(jwtSecretPath, []byte(encoded), 0600)
	if err != nil {
		return err
	}
	jwtSecret = secret
	return nil
}
