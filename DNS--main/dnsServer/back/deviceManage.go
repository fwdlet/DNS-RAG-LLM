package back

import (
	"encoding/json"
	"net/http"
)

// 设备状态常量
const (
	DEVICEPENDING  = 0 // 待批准
	DEVICEAPPROVED = 1 // 已批准
)

// ————公用操作————

// 设备控制
func HandleControlDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string `json:"device_id"`
		Action   string `json:"action"` // "start" or "stop"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数格式错误", http.StatusBadRequest)
		return
	}
	if req.DeviceID == "" || (req.Action != "start" && req.Action != "stop") {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	deviceID := fixDeviceID(req.DeviceID)
	username, role, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	if role != "admin" {
		owner, err := queryDeviceOwner(deviceID)
		if err != nil || owner != username {
			http.Error(w, "无权操作该设备", http.StatusForbidden)
			return
		}
	}
	poolMu.RLock()
	client, ok := connPool[deviceID]
	poolMu.RUnlock()
	if !ok {
		http.Error(w, "设备未在线", http.StatusNotFound)
		return
	}
	msg := map[string]interface{}{
		"type":   "control",
		"action": req.Action,
	}
	client.mu.Lock()
	err = client.conn.WriteJSON(msg)
	client.mu.Unlock()
	if err != nil {
		http.Error(w, "下发控制消息失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ————管理员操作————

// 批准设备
func HandleAdminApproveDevice(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
		User     string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求解析失败", http.StatusBadRequest)
		return
	}
	userRole, err := queryRole(req.User)
	if userRole == "admin" || err != nil {
		http.Error(w, "用户不存在", http.StatusBadRequest)
		return
	}
	deviceID := fixDeviceID(req.DeviceID)
	if err := insertDevice(deviceID, DEVICEAPPROVED, req.User); err != nil {
		http.Error(w, "批准失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 删除已登记设备
func HandleAdminDeleteDevice(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求解析失败", http.StatusBadRequest)
		return
	}
	deviceID := fixDeviceID(req.DeviceID)
	if err := deleteDevice(deviceID); err != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 查询待批准设备列表
func HandleAdminQueryPendingDevice(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	list := queryDevicesWithStatus(DEVICEPENDING)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// 查询所有已登记设备（只显示已批准设备）
func HandleAdminQueryApprovedDevice(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	list := queryDevicesWithStatus(DEVICEAPPROVED)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// 查询在线设备列表（基于WebSocket连接池connPool）
func HandleAdminQueryOnlineDevice(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	poolMu.RLock()
	defer poolMu.RUnlock()
	var list []map[string]interface{}
	for deviceID, client := range connPool {
		client.mu.Lock()
		last := client.lastActive
		client.mu.Unlock()
		list = append(list, map[string]interface{}{
			"device_id":      deviceID,
			"last_heartbeat": last.Format("2006-01-02 15:04:05"),
		})
	}
	if list == nil {
		list = make([]map[string]interface{}, 0)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// 撤销已批准设备
func HandleAdminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求解析失败", http.StatusBadRequest)
		return
	}
	deviceID := fixDeviceID(req.DeviceID)
	if err := revokeDevice(deviceID); err != nil {
		http.Error(w, "撤销失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 查询dns_packets中所有不同的device_id
func HandleAdminQueryDevice(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	devices := queryDeviceIDs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

// ————普通用户操作————

// 查询设备
func HandleUserQueryDevice(w http.ResponseWriter, r *http.Request) {
	username, _, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	devices := queryDevicesByUser(username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

// 普通用户下线自己的设备
func HandleUserOfflineDevice(w http.ResponseWriter, r *http.Request) {
	username, _, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	// 校验该设备是否属于该用户
	deviceID := fixDeviceID(req.DeviceID)
	owner, err := queryDeviceOwner(deviceID)
	if err != nil {
		http.Error(w, "设备不存在", http.StatusNotFound)
		return
	}
	if owner != username {
		http.Error(w, "无权操作该设备", http.StatusForbidden)
		return
	}
	// 下线设备
	poolMu.Lock()
	client, ok := connPool[deviceID]
	if ok {
		client.mu.Lock()
		client.conn.Close()
		client.mu.Unlock()
		delete(connPool, deviceID)
	} else {
		http.Error(w, "设备不在线", http.StatusBadRequest)
	}
	poolMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// 查询当前用户在线设备列表
func HandleUserQueryOnlineDevice(w http.ResponseWriter, r *http.Request) {
	username, _, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	userDevices := queryDevicesByUser(username)
	poolMu.RLock()
	defer poolMu.RUnlock()
	var list []map[string]interface{}
	for _, device := range userDevices {
		_, ok := connPool[device["device_id"].(string)]
		if ok {
			list = append(list, map[string]interface{}{
				"device_id":      device["device_id"].(string),
				"last_heartbeat": connPool[device["device_id"].(string)].lastActive.Format("2006-01-02 15:04:05"),
			})
		}
	}
	if list == nil {
		list = make([]map[string]interface{}, 0)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}
