package back

import (
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 用户登录接口（补充登录日志记录）
func HandlePlatformLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	username, passwordHash, role, status, err := queryUserDetails(req.Username)
	if err != nil {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	if status == USERPENDING {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "pending",
		})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	// 记录登录
	logID, err := queryLastLoginID(username)
	if err == nil && logID > 0 {
		updateLogoutTime(logID, time.Now())
	}
	insertUserLog(username, time.Now())
	token, _ := generateTokenForPlatform(username, role)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":  token,
		"role":   role,
		"status": "active",
	})
}

// 用户登出，记录日志
func HandlePlatformLogout(w http.ResponseWriter, r *http.Request) {
	username, _, err := getNameAndRole(r)
	if err != nil || username == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// 查找最近一次未登出的登录日志
	logID, err := queryLastLoginID(username)
	if err == nil && logID > 0 {
		updateLogoutTime(logID, time.Now())
	}
	w.WriteHeader(http.StatusOK)
}
