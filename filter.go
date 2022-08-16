package main

import (
	"fmt"
)

var ALLIP = IP{0, 0, 0, 0}
var ALLPORT = -1

func FilterPacket(ps *PacketSource, SrcIP, DstIP IP, SrcPort, DstPort int) {
	totalPacketNum := 0
	packetNum := 0
	totalBytes := 0
	bytes := 0
	for p, err := ps.NextPacket(); err == nil; p, err = ps.NextPacket() {
		totalBytes += int(p.incl_len)
		totalPacketNum++
		eth := NewEthernet(p)
		ipv4 := NewIPv4(eth)
		if SrcIP != ALLIP && SrcIP != ipv4.SrcAddress {
			continue
		}
		if DstIP != ALLIP && DstIP != ipv4.DstAddress {
			continue
		}
		if ipv4.NextLayerType() == LayerICMP {
			continue
		}
		var ipip *IPv4
		if ipv4.NextLayerType() == LayerIPv4 {
			ipip = NewIPv4(ipv4)
		}
		if ipv4.NextLayerType() == LayerGRE {
			gre := NewGRE(ipv4)
			ipip = NewIPv4(gre)
		}
		dport, sport := 0, 0
		if ipip.NextLayerType() == LayerTCP {
			tcp := NewTCP(ipip)
			dport = int(tcp.DstPort)
			sport = int(tcp.SrcPort)
		} else if ipv4.NextLayerType() == LayerUDP {
			udp := NewUDP(ipip)
			dport = int(udp.DstPort)
			sport = int(udp.SrcPort)
		}
		if SrcPort != ALLPORT && SrcPort != sport {
			continue
		}
		if DstPort != ALLPORT && DstPort != dport {
			continue
		}
		fmt.Println(p.CaptureTime())
		fmt.Printf("DstAddr: %v SrcAddr: %v Protocal: %04x\n", ipv4.DstAddress.String(), ipv4.SrcAddress.String(), ipv4.ProtocolType)
		fmt.Printf("DstPort: %v SrcPort: %v\n", dport, sport)
		fmt.Println()
		bytes += int(p.incl_len)
		packetNum++
	}
	fmt.Printf("Packet Number:%v Total: %v Percentage: %v\n", packetNum, totalPacketNum, float64(packetNum)/float64(totalPacketNum))
	fmt.Printf("Bytes: %v KB, Total: %v MB, Percentage: %v\n", float64(bytes)/1024, float64(totalBytes)/1024/1024, float64(bytes)/float64(totalBytes))
}

var ALLNUM = 0

func FilterConnection(list ConnectionList, packetNum int, SrcIP, DstIP IP, SrcPort, DstPort int) {
	num, totalnum := 0, 0
	bytes, totalBytes := 0, 0
	for k, v := range list {
		totalnum++
		totalBytes += v.payloadbytes
		if packetNum != ALLNUM && packetNum > v.packet_num {
			continue
		}
		if DstIP != ALLIP && DstIP != k.DstIP {
			continue
		}
		if SrcIP != ALLIP && SrcIP != k.SrcIP {
			continue
		}
		if DstPort != ALLPORT && DstPort != int(k.DstPort) {
			continue
		}
		if SrcPort != ALLPORT && SrcPort != int(k.SrcPort) {
			continue
		}
		fmt.Printf("begin at %v, end at %v\n", v.begin_time, v.end_time)
		fmt.Printf("SrcIP: %v DstIP: %v SrcPort:%v DstPort: %v\n", k.SrcIP.String(), k.DstIP.String(), k.SrcPort, k.DstPort)
		fmt.Printf("packet num: %v, live time %v\n", v.packet_num, v.end_time.Sub(v.begin_time))
		fmt.Println()
		num++
		bytes += v.payloadbytes
	}
	fmt.Printf("connection number: %v, total: %v percentage:%v\n", num, totalnum, float64(num)/float64(totalnum))
	fmt.Printf("Bytes: %v KB, Total: %v MB, Percentage: %v\n", float64(bytes)/1024, float64(totalBytes)/1024/1024, float64(bytes)/float64(totalBytes))

}
