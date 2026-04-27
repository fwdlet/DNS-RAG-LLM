package back

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type config struct {
	HbTime    int `json:"hbTime"`    // 心跳发送间隔（秒）
	ReConTime int `json:"reConTime"` // 重连间隔（秒）
	RsTime    int `json:"rsTime"`    // 重发间隔（秒）
}

// 发送配置
func HandleUserPushConfig(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	deviceID = fixDeviceID(deviceID)
	if deviceID == "" {
		http.Error(w, "无目标设备", http.StatusBadRequest)
		return
	}
	// 用户身份校验：只有设备owner才能下发配置
	username, role, err := getNameAndRole(r)
	if err != nil || username == "" {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	if role == "admin" {
		http.Error(w, "用户不存在", http.StatusUnauthorized)
		return
	}
	owner, err := queryDeviceOwner(deviceID)
	if err != nil {
		http.Error(w, "设备不存在", http.StatusNotFound)
		return
	}
	if owner != username {
		http.Error(w, "无权下发该设备配置", http.StatusForbidden)
		return
	}
	var cfg config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "参数格式错误", http.StatusBadRequest)
		return
	}
	poolMu.RLock()
	client, ok := connPool[deviceID]
	poolMu.RUnlock()
	if !ok {
		http.Error(w, "目标设备未在线", http.StatusNotFound)
		return
	}
	msg := map[string]interface{}{
		"type": "config",
		"data": cfg,
	}
	client.mu.Lock()
	client.hbTimeout = time.Duration(cfg.HbTime) * time.Second * 2
	if err := client.conn.WriteJSON(msg); err != nil {
		client.mu.Unlock()
		http.Error(w, "配置下发失败:"+err.Error(), http.StatusInternalServerError)
		return
	}
	client.mu.Unlock()
	log.Printf("配置已下发给设备 %s: %+v", deviceID, cfg)
	w.WriteHeader(http.StatusOK)
}
