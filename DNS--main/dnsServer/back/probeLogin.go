package back

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// 心跳监听
func StartHBChecker() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		poolMu.Lock()
		for deviceID, client := range connPool {
			client.mu.Lock()
			last := client.lastActive
			timeout := client.hbTimeout
			client.mu.Unlock()
			if now.Sub(last) > timeout {
				log.Printf("设备 %s 超过 %v 秒未心跳，判定为离线", deviceID, timeout.Seconds())
				client.mu.Lock()
				_ = client.conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "心跳超时"), time.Now().Add(time.Second))
				_ = client.conn.Close()
				client.mu.Unlock()
				delete(connPool, deviceID)
			}
		}
		poolMu.Unlock()
	}
}

// 探针端token申请
func HandleProbeLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Iface    string `json:"iface"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求解析失败", http.StatusBadRequest)
		return
	}
	// 校验用户
	username, passwordHash, role, userStatus, err := queryUserDetails(req.Username)
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil || err != nil {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	// 禁止管理员账户拥有设备
	if role == "admin" {
		http.Error(w, "管理员账户不能拥有设备", http.StatusForbidden)
		return
	}
	if userStatus == USERPENDING {
		http.Error(w, "用户未批准", http.StatusForbidden)
		return
	}
	// 校验设备
	deviceStatus, err := checkDeviceStatus(req.Iface)
	if err != nil {
		http.Error(w, "数据库错误", http.StatusInternalServerError)
		return
	}
	if deviceStatus == DEVICEAPPROVED {
		owner, err := queryDeviceOwner(req.Iface)
		if err != nil {
			http.Error(w, "设备不存在", http.StatusNotFound)
			return
		}
		if owner != username {
			http.Error(w, "不是设备拥有者", http.StatusForbidden)
			return
		}
		tokenString, err := generateTokenFroProbe(username, role, req.Iface)
		if err != nil {
			http.Error(w, "生成Token失败", http.StatusInternalServerError)
			return
		}
		resp := struct {
			Token string `json:"token"`
		}{
			Token: tokenString,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	} else if err := insertDevice(req.Iface, DEVICEPENDING, username); err != nil {
		http.Error(w, "设备登记失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"msg": "设备待管理员批准",
	})
}
