package back

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// 用户状态常量
const (
	USERPENDING  = 0 // 待批准
	USERAPPROVED = 1 // 已批准
)

// ————管理员操作————

// 添加用户
func HandleAdminAddUser(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" || (req.Role != "admin" && req.Role != "user") {
		http.Error(w, "参数不完整", http.StatusBadRequest)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err := insertUser(req.Username, string(hash), req.Role, USERAPPROVED); err != nil {
		http.Error(w, "添加失败，用户名可能已存在", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 获取已批准用户
func HandleAdminQueryApprovedUser(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	approvedUsers := queryUsersWithStatus(USERAPPROVED)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(approvedUsers)
}

// 查询在线用户（logout_time为空即在线）
func HandleAdminQueryOnlineUser(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	users := queryLogoutTimeNull()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// 修改密码
func HandleAdminUpdatePwd(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.NewPassword == "" {
		http.Error(w, "参数不完整", http.StatusBadRequest)
		return
	}
	if updatePassword(req.Username, req.NewPassword) != nil {
		http.Error(w, "修改失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 批准用户
func HandleAdminApproveUser(w http.ResponseWriter, r *http.Request) {
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
	if approveUser(req.Username) != nil {
		http.Error(w, "批准失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 获取待审核用户
func HandleAdminQueryPendingUser(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	pendingUsers := queryUsersWithStatus(USERPENDING)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pendingUsers)
}

// 删除用户
func HandleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
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
	// 删除用户及其相关设备、日志
	if err := deleteUserAndRelated(req.Username); err != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ————普通用户操作————

// 修改密码
func HandleUserUpdatePwd(w http.ResponseWriter, r *http.Request) {
	username, _, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	if req.NewPassword == "" {
		http.Error(w, "参数不完整", http.StatusBadRequest)
		return
	}
	if updatePassword(username, req.NewPassword) != nil {
		http.Error(w, "修改失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 用户注册
func HandleUserRegister(w http.ResponseWriter, r *http.Request) {
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
	if req.Username == "" || req.Password == "" {
		http.Error(w, "参数不完整", http.StatusBadRequest)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err := insertUser(req.Username, string(hash), "user", USERPENDING); err != nil {
		http.Error(w, "注册失败，用户名可能已存在", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
