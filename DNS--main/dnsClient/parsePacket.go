package main

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	SrcIP    string
	SrcPort  string
	DstIP    string
	DstPort  string
	Protocol string
	DNS      *layers.DNS
	Ts       time.Time
}

// 解析DNS包各字段
func parseDNSPacket(packet gopacket.Packet) *Packet {
	netLayer := packet.NetworkLayer()
	transLayer := packet.TransportLayer()
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}
	dns, _ := dnsLayer.(*layers.DNS)
	return &Packet{
		SrcIP:    netLayer.NetworkFlow().Src().String(),
		SrcPort:  transLayer.TransportFlow().Src().String(),
		DstIP:    netLayer.NetworkFlow().Dst().String(),
		DstPort:  transLayer.TransportFlow().Dst().String(),
		Protocol: transLayer.LayerType().String(),
		DNS:      dns,
		Ts:       time.Now(),
	}
}
