package back

import (
	"encoding/json"
	"net/http"
)

// 查询用户登录日志
func HandleAdminQueryUserLog(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "缺少username", http.StatusBadRequest)
		return
	}
	logs := queryUserLoginLogs(username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// 删除用户登录日志
func HandleAdminDeleteUserLog(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "缺少用户名", http.StatusBadRequest)
		return
	}
	if err := deleteUserLog(req.Username); err != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 查询设备日志
func HandleAdminQueryDeviceLog(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	deviceID := r.URL.Query().Get("device_id")
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")
	list := queryDeviceLog(deviceID, start, end)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}
