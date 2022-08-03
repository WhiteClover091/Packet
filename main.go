package main

import (
	"fmt"
	"log"
)

func main() {
	packetSource := ReadPcapData("2022-08-02-11-04-45-11.122.30.47.pcap")
	// fmt.Println(packet.pcaprec_hdr_s)
	// fmt.Println(packet.CaptureTime())
	packet, err := packetSource.NextPacket()
	if err != nil {
		log.Fatal(err)
	}
	ethernet := NewEthernet(packet)
	fmt.Println(ethernet.DstMAC, ethernet.SrcMAC, ethernet.EtherType == 0x0800)
	ipv4 := NewIPv4FromEthernet(*ethernet)
	fmt.Println(ipv4.DstAddress, ipv4.SrcAddress, ipv4.ProtocolType)
	fmt.Printf("%02x\n", ipv4.ProtocolType)
	ipip := NewIPv4FromIPv4(ipv4)
	fmt.Println(ipip.DstAddress, ipip.SrcAddress, ipip.ProtocolType)
	fmt.Printf("%02x\n", ipip.ProtocolType)
	tcp := NewTCPFromIPv4(ipip)
	fmt.Println(tcp.SrcPort, tcp.DstPort, tcp.ACK, tcp.PSH, tcp.SYN, tcp.FIN)
	packet, _ = packetSource.NextPacket()
	ethernet = NewEthernet(packet)
	fmt.Println(ethernet.DstMAC, ethernet.SrcMAC, ethernet.EtherType == 0x0800)
	ipv4 = NewIPv4FromEthernet(*ethernet)
	fmt.Println(ipv4.DstAddress, ipv4.SrcAddress, ipv4.ProtocolType)
	gre := NewGRE(ipv4)
	fmt.Printf("%04x\n", gre.ProtocalType)
}
