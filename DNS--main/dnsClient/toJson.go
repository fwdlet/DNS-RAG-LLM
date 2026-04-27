package main

import (
	"time"
)

// Packet 结构体用于存储解析后的DNS数据包信息
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

// 转换为指定JSON格式
func (p *Packet) toJson(deviceID, version string) *jsonPacket {
	// 解析问题
	var que *question
	if len(p.DNS.Questions) > 0 {
		q := p.DNS.Questions[0]
		que = &question{
			Name:  string(q.Name),
			Type:  q.Type.String(),
			Class: q.Class.String(),
		}
	}
	// 解析应答
	answers := []answer{}
	for _, ans := range p.DNS.Answers {
		answers = append(answers, answer{
			Name:    string(ans.Name),
			Type:    ans.Type.String(),
			Class:   ans.Class.String(),
			TTL:     ans.TTL,
			Address: ans.IP.String(),
		})
	}
	// authorities
	authorities := []answer{}
	for _, auth := range p.DNS.Authorities {
		authorities = append(authorities, answer{
			Name:    string(auth.Name),
			Type:    auth.Type.String(),
			Class:   auth.Class.String(),
			TTL:     auth.TTL,
			Address: auth.IP.String(),
		})
	}
	// additionals
	additionals := []answer{}
	for _, add := range p.DNS.Additionals {
		additionals = append(additionals, answer{
			Name:    string(add.Name),
			Type:    add.Type.String(),
			Class:   add.Class.String(),
			TTL:     add.TTL,
			Address: add.IP.String(),
		})
	}
	return &jsonPacket{
		Metadata: metadata{
			DeviceID:         deviceID,
			CollectorVersion: version,
			Timestamp:        p.Ts.UTC().Format(time.RFC3339Nano),
		},
		Network: network{
			SrcIP:    p.SrcIP,
			SrcPort:  p.SrcPort,
			DstIP:    p.DstIP,
			DstPort:  p.DstPort,
			Protocol: p.Protocol,
		},
		DNS: dnsInfo{
			TransactionID: p.DNS.ID,
			Opcode:        p.DNS.OpCode.String(),
			Flags: dnsFlags{
				QR: p.DNS.QR,
				AA: p.DNS.AA,
				TC: p.DNS.TC,
				RD: p.DNS.RD,
				RA: p.DNS.RA,
			},
			Rcode:       p.DNS.ResponseCode.String(),
			Question:    que,
			Answers:     answers,
			Authorities: authorities,
			Additionals: additionals,
		},
	}
}
