package back

import (
	"encoding/json"
	"fmt"
	"time"
)

type metadata struct {
	DeviceID         string `json:"device_id"`
	CollectorVersion string `json:"collector_version"`
	Timestamp        string `json:"timestamp"`
}
type network struct {
	SrcIP    string `json:"src_ip"`
	SrcPort  string `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  string `json:"dst_port"`
	Protocol string `json:"protocol"`
}
type dnsFlags struct {
	QR bool `json:"qr"`
	AA bool `json:"aa"`
	TC bool `json:"tc"`
	RD bool `json:"rd"`
	RA bool `json:"ra"`
}
type question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}
type answer struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Class   string `json:"class"`
	TTL     uint32 `json:"ttl"`
	Address string `json:"address"`
}
type dnsInfo struct {
	TransactionID uint16    `json:"transaction_id"`
	Opcode        string    `json:"opcode"`
	Flags         dnsFlags  `json:"flags"`
	Rcode         string    `json:"rcode"`
	Question      *question `json:"question"`
	Answers       []answer  `json:"answers"`
	Authorities   []answer  `json:"authorities"`
	Additionals   []answer  `json:"additionals"`
}
type jsonPacket struct {
	Metadata metadata `json:"metadata"`
	Network  network  `json:"network"`
	DNS      dnsInfo  `json:"dns"`
}

// 保存包
func savePacket(msg interface{}) error{
	var pkt jsonPacket
	packet_json, _ := json.Marshal(msg)
	if err := json.Unmarshal(packet_json, &pkt); err != nil {
		return err
	}
	timestamp, err := time.Parse(time.RFC3339Nano, pkt.Metadata.Timestamp)
	if err != nil {
		return fmt.Errorf("时间格式错误: %v", err)
	}
	err = insertPacket(&pkt, string(packet_json), timestamp)
	if err != nil {
		return fmt.Errorf("保存数据包失败: %v", err)
	}
	return nil
}
