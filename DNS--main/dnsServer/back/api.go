package back

import (
	"net/http"
)

func RegisterRoutes() {
	// 探针端接口
	http.HandleFunc("/probe/ws", HandleWS)
	http.HandleFunc("/probe/login", HandleProbeLogin)
	// 平台端接口
	http.HandleFunc("/api/platform/login", HandlePlatformLogin)
	http.HandleFunc("/api/platform/logout", HandlePlatformLogout)
	// ————管理员————
	// 设备管理接口
	http.HandleFunc("/api/admin/device/logs/query", HandleAdminQueryDeviceLog)
	http.HandleFunc("/api/admin/device/pending/query", HandleAdminQueryPendingDevice)
	http.HandleFunc("/api/admin/device/approve", HandleAdminApproveDevice)
	http.HandleFunc("/api/admin/device/delete", HandleAdminDeleteDevice)
	http.HandleFunc("/api/admin/device/approved/query", HandleAdminQueryApprovedDevice)
	http.HandleFunc("/api/admin/device/online/query", HandleAdminQueryOnlineDevice)
	http.HandleFunc("/api/admin/device/revoke", HandleAdminRevokeDevice)
	http.HandleFunc("/api/admin/device/query", HandleAdminQueryDevice)
	// 用户管理接口
	http.HandleFunc("/api/admin/user/approved/query", HandleAdminQueryApprovedUser)
	http.HandleFunc("/api/admin/user/log/query", HandleAdminQueryUserLog)
	http.HandleFunc("/api/admin/user/online/query", HandleAdminQueryOnlineUser)
	http.HandleFunc("/api/admin/user/pwd/update", HandleAdminUpdatePwd)
	http.HandleFunc("/api/admin/user/delete", HandleAdminDeleteUser)
	http.HandleFunc("/api/admin/user/log/delete", HandleAdminDeleteUserLog)
	http.HandleFunc("/api/admin/user/add", HandleAdminAddUser)
	http.HandleFunc("/api/admin/user/approve", HandleAdminApproveUser)
	http.HandleFunc("/api/admin/user/pending/query", HandleAdminQueryPendingUser)
	// 包管理接口
	http.HandleFunc("/api/admin/packet/query", HandleAdminQueryPacket)
	http.HandleFunc("/api/admin/packet/delete", HandleAdminDeletePacket)
	// jwt管理接口
	http.HandleFunc("/api/admin/jwt/regenerate", HandleAdminRegenerateJWTSecret)
	// ————用户————
	// 设备管理接口
	http.HandleFunc("/api/user/device/config/push", HandleUserPushConfig)
	http.HandleFunc("/api/user/device/query", HandleUserQueryDevice)
	http.HandleFunc("/api/user/device/offline", HandleUserOfflineDevice)
	http.HandleFunc("/api/user/device/online/query", HandleUserQueryOnlineDevice)

	// 包管理接口
	http.HandleFunc("/api/user/packet/query", HandleUserQueryPacket)
	http.HandleFunc("/api/user/packet/delete", HandleUserDeletePacket)
	// 登陆相关管理接口
	http.HandleFunc("/api/user/pwd/update", HandleUserUpdatePwd)
	http.HandleFunc("/api/user/register", HandleUserRegister)
	// 公用
	http.HandleFunc("/api/packets/detail", HandleQueryPacketDetail)
	http.HandleFunc("/api/device/control", HandleControlDevice)
}
