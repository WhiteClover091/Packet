package main

import (
	"fmt"
	"time"
)

func main() {
	packetSource := ReadPcapData("2022-08-02-11-04-45-11.122.30.101.pcap")
	// fmt.Println(packet.pcaprec_hdr_s)
	// fmt.Println(packet.CaptureTime())
	begin := time.Now()
	connectionlist := make(ConnectionList)
	i := 0
	for packet, err := packetSource.NextPacket(); err == nil; packet, err = packetSource.NextPacket() {
		connection := GetConnection(packet)
		if connection.layer == LayerICMP {
			continue
		}
		_, ok := connectionlist[connection]
		if !ok {
			connectionlist[connection] = ConnectionInfo{packet_num: 1, begin_time: packet.CaptureTime(), payloadbytes: int(packet.orig_len), end_time: packet.CaptureTime()}
		} else {
			connectioninfo := connectionlist[connection]
			connectioninfo.packet_num++
			connectioninfo.end_time = packet.CaptureTime()
			connectioninfo.payloadbytes += int(packet.incl_len)
			connectionlist[connection] = connectioninfo
		}
		i++
	}
	filteredlist := connectionlist.filter(8, 20*time.Second)
	// for k, v := range filteredlist {
	// 	fmt.Printf("DstIP: %d.%d.%d.%d\t SrcIP: %d.%d.%d.%d\t DstPort:%d\t SrcPort:%d\t ", k.DstIP[0], k.DstIP[1], k.DstIP[2], k.DstIP[3], k.SrcIP[0], k.SrcIP[1], k.SrcIP[2], k.SrcIP[3], k.DstPort, k.SrcPort)
	// 	if k.layer == LayerTCP {
	// 		fmt.Printf("TCP\n ")
	// 	} else if k.layer == LayerUDP {
	// 		fmt.Printf("UDP\n ")
	// 	} else if k.layer == LayerICMP {
	// 		fmt.Printf("ICMP\n ")
	// 	}
	// 	fmt.Printf("begin at %v, end at %v, last for %v, total Packet: %d, total bytes: %d\n", v.begin_time, v.end_time, v.end_time.Sub(v.begin_time), v.packet_num, v.payloadbytes)
	// }
	fmt.Printf("Total Package: %d, Total Bytes: %d MB\n", filteredlist.totalPacket(), filteredlist.totalBytes()/1024/1024)
	fmt.Printf("MaxPacketNumber: %d, MaxLiveTime: %v, Total Package: %d Total Bytes: %d MB\n", connectionlist.MaxPacketNumber(), connectionlist.MaxLiveTime(), connectionlist.totalPacket(), connectionlist.totalBytes()/1024/1024)
	end := time.Now()
	fmt.Println(end.Sub(begin))
	// ethernet := NewEthernet(packet)
	// fmt.Printf("%v\n", ethernet.DstMAC)
	// fmt.Println(ethernet.DstMAC, ethernet.SrcMAC, ethernet.EtherType == 0x0800)
	// ipv4 := NewIPv4(ethernet)
	// fmt.Println(ipv4.DstAddress, ipv4.SrcAddress, ipv4.ProtocolType)
	// fmt.Printf("%02x\n", ipv4.ProtocolType)
	// ipip := NewIPv4(ipv4)
	// fmt.Println(ipip.DstAddress, ipip.SrcAddress, ipip.ProtocolType)
	// fmt.Printf("%02x\n", ipip.ProtocolType)
	// tcp := NewTCP(ipip)
	// fmt.Println(tcp.SrcPort, tcp.DstPort, tcp.ACK, tcp.PSH, tcp.SYN, tcp.FIN)
	// packet, _ = packetSource.NextPacket()
	// ethernet = NewEthernet(packet)
	// fmt.Println(ethernet.DstMAC, ethernet.SrcMAC, ethernet.EtherType == 0x0800)
	// ipv4 = NewIPv4(ethernet)
	// fmt.Println(ipv4.DstAddress, ipv4.SrcAddress, ipv4.ProtocolType)
	// gre := NewGRE(ipv4)
	// fmt.Printf("%04x\n", gre.ProtocalType)
}
