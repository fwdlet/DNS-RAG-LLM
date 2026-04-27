package back

import (
	"net"
	"strings"
	"time"
)

// 获取本机第一个非回环IPv4地址
func GetLocalIP() string {
	interfaceName := "ens33"
	ifaces, err := net.Interfaces()
	if err != nil {
		return "localhost"
	}
	for _, iface := range ifaces {
		if iface.Name == interfaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				return "localhost"
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok || ipNet.IP.IsLoopback() {
					continue
				}
				if ipNet.IP.To4() != nil {
					return ipNet.IP.String()
				}
			}
			return "localhost"
		}
	}
	return "localhost"
}

// 解析时间
func parseTime(s string) time.Time {
	// 支持datetime-local格式
	s = strings.Replace(s, "T", " ", 1)
	t, _ := time.Parse("2006-01-02 15:04", s)
	return t
}

// device_id修正工具
func fixDeviceID(deviceID string) string {
	if strings.Contains(deviceID, "DeviceNPF_") {
		return strings.Replace(deviceID, "DeviceNPF_", `\Device\NPF_`, -1)
	}
	return deviceID
}
