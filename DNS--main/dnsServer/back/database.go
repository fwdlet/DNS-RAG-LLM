package back

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// 初始化数据库
func InitDB(dsn ...string) {
	var useDSN string // 数据库dsn
	if len(dsn) > 0 && dsn[0] != "" {
		useDSN = dsn[0]
	}
	var err error
	db, err = sql.Open("mysql", useDSN)
	if err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}
}

// 保存接收到的包
func insertPacket(pkt *jsonPacket, jsonFile string, timestamp time.Time) error {
	_, err := db.Exec("INSERT INTO dns_packets (timestamp, device_id, collector_ver, src_ip, src_port, dst_ip, dst_port, protocol, dns_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		timestamp,
		pkt.Metadata.DeviceID,
		pkt.Metadata.CollectorVersion,
		pkt.Network.SrcIP,
		pkt.Network.SrcPort,
		pkt.Network.DstIP,
		pkt.Network.DstPort,
		pkt.Network.Protocol,
		jsonFile,
	)
	if err != nil {
		log.Println("insertPacket error:", err)
	}
	return err
}

// 插入或更新设备为指定状态，支持user字段
func insertDevice(deviceID string, status int, user string) error {
	deviceID = fixDeviceID(deviceID)
	var err error
	_, err = db.Exec(`
		INSERT INTO device (device_id, status, register_time, user)
		VALUES (?, ?, NOW(), ?)
		ON DUPLICATE KEY UPDATE status=VALUES(status), user=VALUES(user)
	`, deviceID, status, user)
	if err != nil {
		log.Println("insertDevice error:", err)
	}
	return err
}

// 查询设备状态
func checkDeviceStatus(deviceID string) (int, error) {
	var status int
	err := db.QueryRow("SELECT status FROM device WHERE device_id = ?", deviceID).Scan(&status)
	if err != nil && err != sql.ErrNoRows {
		log.Println("checkDeviceStatus error:", err)
	}
	if err == sql.ErrNoRows {
		return -1, nil // 不存在
	}
	if err != nil {
		return -1, err
	}
	return status, nil
}

// 查询包列表
func queryPacketList(deviceID, start, end string) []map[string]interface{} {
	var args []interface{}
	query := "SELECT id, device_id, timestamp, src_ip, dst_ip, protocol FROM dns_packets WHERE 1=1"
	if deviceID != "" {
		query += " AND device_id = ?"
		args = append(args, deviceID)
	}
	if start != "" {
		query += " AND timestamp >= ?"
		args = append(args, parseTime(start))
	}
	if end != "" {
		query += " AND timestamp <= ?"
		args = append(args, parseTime(end))
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Println("queryPacketList error:", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var list []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var id int
		var ts time.Time
		var srcIP, dstIP, protocol string
		rows.Scan(&id, &deviceID, &ts, &srcIP, &dstIP, &protocol)
		list = append(list, map[string]interface{}{
			"id":        id,
			"device_id": deviceID,
			"timestamp": ts.Format("2006-01-02 15:04:05"),
			"src_ip":    srcIP,
			"dst_ip":    dstIP,
			"protocol":  protocol,
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return list
	}
}

// 查询所有有上传过包的设备ID
func queryDeviceIDs() []string {
	rows, err := db.Query("SELECT DISTINCT device_id FROM dns_packets")
	if err != nil {
		log.Println("queryDeviceIDs error:", err)
		return make([]string, 0)
	}
	defer rows.Close()
	var devices []string
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var id string
		rows.Scan(&id)
		devices = append(devices, id)
	}
	if isEmpty {
		return make([]string, 0)
	} else {
		return devices
	}
}

// 查询单个包详细内容
func queryPacketDetail(id string) (string, error) {
	var dnsData string
	err := db.QueryRow("SELECT dns_data FROM dns_packets WHERE id = ?", id).Scan(&dnsData)
	if err != nil {
		log.Println("queryPacketDetail error:", err)
		return "", err
	}
	return dnsData, nil
}

// 删除设备
func deleteDevice(deviceID string) error {
	_, err := db.Exec(`DELETE FROM device WHERE device_id=?`, deviceID)
	if err != nil {
		log.Println("deleteDevice error:", err)
	}
	return err
}

// 设备状态改为待批准
func revokeDevice(deviceID string) error {
	_, err := db.Exec(`UPDATE device SET status=? WHERE device_id=?`, DEVICEPENDING, deviceID)
	if err != nil {
		log.Println("revokeDevice error:", err)
	}
	return err
}

// 查询指定状态的设备
func queryDevicesWithStatus(status int) []map[string]interface{} {
	rows, err := db.Query("SELECT device_id, status, register_time, user FROM device WHERE status = ?", status)
	if err != nil {
		log.Println("queryDevicesWithStatus error:", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var list []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var id, regTime, user string
		var status int
		rows.Scan(&id, &status, &regTime, &user)
		id = fixDeviceID(id)
		list = append(list, map[string]interface{}{
			"device_id":     id,
			"status":        status,
			"register_time": regTime,
			"user":          user,
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return list
	}
}

// 查询属于某用户的设备
func queryDevicesByUser(username string) []map[string]interface{} {
	rows, err := db.Query("SELECT device_id, status, register_time FROM device WHERE user = ?", username)
	if err != nil {
		log.Println("queryDevicesByUser error:", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var list []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var id, regTime string
		var status int
		rows.Scan(&id, &status, &regTime)
		id = fixDeviceID(id)
		list = append(list, map[string]interface{}{
			"device_id":     id,
			"status":        status,
			"register_time": regTime,
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return list
	}
}

// 查询属于某用户的所有包（通过设备user字段）
func queryPacketsByUser(username string) []map[string]interface{} {
	rows, err := db.Query(`
		SELECT p.id, p.timestamp, p.src_ip, p.dst_ip, p.protocol, p.device_id
		FROM dns_packets p
		JOIN device d ON p.device_id = d.device_id
		WHERE d.user = ?
		ORDER BY p.timestamp DESC
	`, username)
	if err != nil {
		log.Println("queryPacketsByUser error:", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var list []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var id int
		var ts time.Time
		var srcIP, dstIP, protocol, deviceID string
		rows.Scan(&id, &ts, &srcIP, &dstIP, &protocol, &deviceID)
		list = append(list, map[string]interface{}{
			"id":        id,
			"timestamp": ts.Format("2006-01-02 15:04:05"),
			"src_ip":    srcIP,
			"dst_ip":    dstIP,
			"protocol":  protocol,
			"device_id": deviceID,
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return list
	}
}

// 获取用户信息
func queryUserDetails(username string) (string, string, string, int, error) {
	var passwordHash, role string
	var status int
	err := db.QueryRow("SELECT password_hash, role, status FROM user WHERE username = ?", username).Scan(&passwordHash, &role, &status)
	if err != nil {
		log.Println("queryUserByUsername error:", err)
		return "", "", "", -1, err
	}
	return username, passwordHash, role, status, nil
}

// 添加用户
func insertUser(username, passwordHash, role string, status int) error {
	_, err := db.Exec("INSERT INTO user (username, password_hash, role, status) VALUES (?, ?, ?, ?)", username, passwordHash, role, status)
	if err != nil {
		log.Println("insertUser error:", err)
	}
	return err
}

// 查询所有用户
func queryUsersWithStatus(status int) []map[string]interface{} {
	rows, err := db.Query("SELECT username, role, create_time FROM user WHERE status = ?", status)
	if err != nil {
		log.Println("queryUsersWithStatus error:", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var users []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var username, role, createTime string
		rows.Scan(&username, &role, &createTime)
		users = append(users, map[string]interface{}{
			"username":    username,
			"role":        role,
			"create_time": createTime,
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return users
	}
}

// 插入用户登录日志
func insertUserLog(username string, loginTime time.Time) error {
	_, err := db.Exec("INSERT INTO logUser (username, login_time) VALUES (?, ?)", username, loginTime)
	if err != nil {
		log.Println("insertUserLog error:", err)
		return err
	}
	return nil
}

// 查找最近一次未登出的登录日志ID
func queryLastLoginID(username string) (int, error) {
	var logID int
	err := db.QueryRow("SELECT id FROM logUser WHERE username=? AND logout_time IS NULL ORDER BY login_time DESC LIMIT 1", username).Scan(&logID)
	if err != nil {
		log.Println("queryLastLoginLogID error:", err)
		return -1, err
	}
	return logID, nil
}

// 更新登出时间
func updateLogoutTime(logID int, logoutTime time.Time) error {
	_, err := db.Exec("UPDATE logUser SET logout_time=? WHERE id=?", logoutTime, logID)
	if err != nil {
		log.Println("updateLogoutTime error:", err)
		return err
	}
	return nil
}

// 批量删除包
func deletePackets(ids []int) error {
	query := "DELETE FROM dns_packets WHERE id IN (?"
	args := []interface{}{ids[0]}
	for i := 1; i < len(ids); i++ {
		query += ",?"
		args = append(args, ids[i])
	}
	query += ")"
	_, err := db.Exec(query, args...)
	if err != nil {
		log.Println("deletePackets error: ", err)
		return err
	}
	return nil
}

// 查询用户登录日志
func queryUserLoginLogs(username string) []map[string]interface{} {
	rows, err := db.Query("SELECT username, login_time, logout_time FROM logUser WHERE username = ? ORDER BY login_time DESC", username)
	if err != nil {
		log.Println("queryUserLoginLogs error:", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var logs []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var uname string
		var loginTime, logoutTime time.Time
		rows.Scan(&uname, &loginTime, &logoutTime)
		logs = append(logs, map[string]interface{}{
			"username":    uname,
			"login_time":  loginTime.Format("2006-01-02 15:04:05"),
			"logout_time": logoutTime.Format("2006-01-02 15:04:05"),
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return logs
	}
}

// 删除用户及其相关设备、日志
func deleteUserAndRelated(username string) error {
	_, err1 := db.Exec("DELETE FROM device WHERE user=?", username)
	deleteUserLog(username)
	_, err2 := db.Exec("DELETE FROM user WHERE username=?", username)
	if err1 != nil {
		log.Println("deleteUserAndRelated error: ", err1)
		return err1
	}
	if err2 != nil {
		log.Println("deleteUserAndRelated error: ", err2)
		return err2
	}
	return nil
}

// 删除用户登录日志
func deleteUserLog(username string) error {
	_, err := db.Exec("DELETE FROM logUser WHERE username=? AND logout_time IS NOT NULL", username)
	if err != nil {
		log.Println("deleteUserLog error:", err)
		return err
	}
	return nil
}

// 查询用户权限
func queryRole(username string) (string, error) {
	var role string
	err := db.QueryRow("SELECT role FROM user WHERE username = ?", username).Scan(&role)
	if err != nil {
		log.Println("queryRole error:", err)
		return "", err
	}
	return role, nil
}

// 查询设备所属用户
func queryDeviceOwner(deviceID string) (string, error) {
	var owner string
	err := db.QueryRow("SELECT user FROM device WHERE device_id = ?", deviceID).Scan(&owner)
	if err != nil {
		log.Println("queryDeviceOwner error:", err)
		return "", err
	}
	return owner, nil
}

// 更新用户密码
func updatePassword(username, password string) error {
	password_hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_, err := db.Exec("UPDATE user SET password_hash = ? WHERE username = ?", string(password_hash), username)
	if err != nil {
		log.Println("updatePassword error:", err)
		return err
	}
	return nil
}

// 校验某个用户的包
func checkValidPackets(username string, ids []int) []int {
	query := `
		SELECT p.id
		FROM dns_packets p
		JOIN device d ON p.device_id = d.device_id
		WHERE d.user = ? AND p.id IN (?
	`
	args := []interface{}{username, ids[0]}
	for i := 1; i < len(ids); i++ {
		query += ",?"
		args = append(args, ids[i])
	}
	query += ")"
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Println("checkWhosePackets error: ", err)
		return make([]int, 0)
	}
	defer rows.Close()
	var validIDs []int
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var id int
		rows.Scan(&id)
		validIDs = append(validIDs, id)
	}
	if isEmpty {
		return make([]int, 0)
	} else {
		return validIDs
	}
}

// 查询在线用户
func queryLogoutTimeNull() []map[string]interface{} {
	rows, err := db.Query("SELECT DISTINCT username FROM logUser WHERE logout_time IS NULL")
	if err != nil {
		log.Println("queryLogoutTimeNull error: ", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var usersName []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var username string
		rows.Scan(&username)
		usersName = append(usersName, map[string]interface{}{
			"username": username,
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return usersName
	}
}

// 批准用户
func approveUser(username string) error {
	_, err := db.Exec("UPDATE user SET status=? WHERE username=?", USERAPPROVED, username)
	if err != nil {
		log.Println("approveUser error: ", err)
		return err
	}
	return nil
}

func queryDeviceLog(deviceID, start, end string) []map[string]interface{} {
	var args []interface{}
	query := "SELECT device_id, DATE(timestamp) as day, COUNT(*) as file_count FROM dns_packets WHERE 1=1"
	if deviceID != "" {
		query += " AND device_id = ?"
		args = append(args, deviceID)
	}
	if start != "" {
		query += " AND timestamp >= ?"
		args = append(args, parseTime(start))
	}
	if end != "" {
		query += " AND timestamp <= ?"
		args = append(args, parseTime(end))
	}
	query += " GROUP BY device_id, day ORDER BY day DESC"
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Println("queryDeviceLog error: ", err)
		return make([]map[string]interface{}, 0)
	}
	defer rows.Close()
	var list []map[string]interface{}
	isEmpty := true
	for rows.Next() {
		isEmpty = false
		var deviceID, day string
		var fileCount int
		rows.Scan(&deviceID, &day, &fileCount)
		list = append(list, map[string]interface{}{
			"device_id":  deviceID,
			"time":       day,
			"file_count": fileCount,
		})
	}
	if isEmpty {
		return make([]map[string]interface{}, 0)
	} else {
		return list
	}
}
