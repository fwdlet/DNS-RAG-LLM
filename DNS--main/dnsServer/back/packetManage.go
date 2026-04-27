package back

import (
	"encoding/json"
	"net/http"
)

// ————公用操作————

// 查询单个包详细内容
func HandleQueryPacketDetail(w http.ResponseWriter, r *http.Request) {
	username, role, err := getNameAndRole(r)
	if err != nil || role != "admin" && role != "user" || username == "" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "缺少id参数", http.StatusBadRequest)
		return
	}
	dnsData, err := queryPacketDetail(id)
	if err != nil {
		http.Error(w, "未找到包", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"dns_data": dnsData,
	})
}

// ————管理员操作————

// 批量删除包
func HandleAdminDeletePacket(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		IDs []int `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	if deletePackets(req.IDs) != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// 查询包
func HandleAdminQueryPacket(w http.ResponseWriter, r *http.Request) {
	_, role, err := getNameAndRole(r)
	if err != nil || role != "admin" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	deviceID := r.URL.Query().Get("device_id")
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")
	list := queryPacketList(deviceID, start, end)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// ————普通用户操作————

// 查询包
func HandleUserQueryPacket(w http.ResponseWriter, r *http.Request) {
	username, _, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	list := queryPacketsByUser(username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// 批量删除包
func HandleUserDeletePacket(w http.ResponseWriter, r *http.Request) {
	username, _, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	var req struct {
		IDs []int `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	// 校验每个包是否属于该用户
	validIDs := checkValidPackets(username, req.IDs)
	if len(validIDs) == 0 {
		http.Error(w, "无可删除包", http.StatusForbidden)
		return
	}
	if deletePackets(validIDs) != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
