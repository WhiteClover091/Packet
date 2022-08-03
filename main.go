package main

import (
	"fmt"
	"log"
	"time"
)

func main() {
	packetSource := ReadPcapData("2022-08-02-11-04-45-11.122.30.101.pcap")
	// fmt.Println(packet.pcaprec_hdr_s)
	// fmt.Println(packet.CaptureTime())
	packet, err := packetSource.NextPacket()
	if err != nil {
		log.Fatal(err)
	}
	begin := time.Now()
	for i := 0; err == nil; packet, err = packetSource.NextPacket() {
		fmt.Println(i, ":")
		PacketDump(packet)
		fmt.Println()
		i++
	}
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
