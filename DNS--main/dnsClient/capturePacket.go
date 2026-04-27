package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// 支持停止的抓包
func captureDNSWithStop(iface string, packetChan chan<- gopacket.Packet, stopChan <-chan struct{}) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		close(packetChan)
		return
	}
	defer handle.Close()
	handle.SetBPFFilter("udp port 53")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("正在捕获DNS数据包...")
	for {
		select {
		case packet, ok := <-packetSource.Packets():
			if !ok {
				close(packetChan)
				return
			}
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				packetChan <- packet
			}
		case <-stopChan:
			close(packetChan)
			return
		}
	}
}
