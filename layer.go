package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

const (
	EthernetTypeIPv4     = 0x0800
	EthernetTypeIpv6     = 0x86DD
	IPProtocolTypeICMP   = 0x01
	IPProtocolTypeIPv4   = 0x04
	IPProtocolTypeTCP    = 0x06
	IPProtocolTypeUDP    = 0x11
	IPProtocolTypeIPv6   = 0x29
	IPProtocolTypeGRE    = 0x2F
	IPProtocolTypeICMPv6 = 0x3A
)

var IPProtocolType []byte = []byte{0x01, 0x04, 0x06, 0x11, 0x29, 0x2F, 0x3A}

type Ethernet struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16
	Payload   []byte
}

func NewEthernet(p *Packet) *Ethernet {
	var ethernet Ethernet
	ethernet.DstMAC = p.packetData[:6]
	ethernet.SrcMAC = p.packetData[6:12]
	ethernet.EtherType = binary.BigEndian.Uint16(p.packetData[12:])
	if ethernet.EtherType != EthernetTypeIPv4 && ethernet.EtherType != EthernetTypeIpv6 {
		errMessage := fmt.Sprintf("Ethernet: Unsupported EthernetType: 0x%04x", ethernet.EtherType)
		log.Fatal(errMessage)
	}
	ethernet.Payload = p.packetData[14:]
	return &ethernet
}

type IPv4 struct {
	SrcAddress   net.IP
	DstAddress   net.IP
	ProtocolType byte
	Payload      []byte
}

func NewIPv4FromEthernet(ethernet Ethernet) *IPv4 {
	var ipv4 IPv4
	ipv4.SrcAddress = ethernet.Payload[12:16]
	ipv4.DstAddress = ethernet.Payload[16:20]
	ipv4.ProtocolType = ethernet.Payload[9]
	var ok bool
	for _, protocol := range IPProtocolType {
		if ipv4.ProtocolType == protocol {
			ok = true
		}
	}
	if !ok {
		errMessage := fmt.Sprintf("IPv4: Unsupported IPProtocolType: 0x%02x", ipv4.ProtocolType)
		log.Fatal(errMessage)
	}
	ipv4.Payload = ethernet.Payload[20:]
	return &ipv4
}

func NewIPv4FromIPv4(ip *IPv4) *IPv4 {
	var ipv4 IPv4
	ipv4.SrcAddress = ip.Payload[12:16]
	ipv4.DstAddress = ip.Payload[16:20]
	ipv4.ProtocolType = ip.Payload[9]
	var ok bool
	for _, protocol := range IPProtocolType {
		if ipv4.ProtocolType == protocol {
			ok = true
		}
	}
	if !ok {
		errMessage := fmt.Sprintf("IPv4: Unsupported IPProtocolType: 0x%02x", ipv4.ProtocolType)
		log.Fatal(errMessage)
	}
	ipv4.Payload = ip.Payload[20:]
	return &ipv4
}

type TCP struct {
	SrcPort uint16
	DstPort uint16
	ACK     bool
	PSH     bool
	SYN     bool
	FIN     bool
	Payload []byte
}

func NewTCPFromIPv4(ipv4 *IPv4) *TCP {
	var tcp TCP
	tcp.SrcPort = binary.BigEndian.Uint16(ipv4.Payload)
	tcp.DstPort = binary.BigEndian.Uint16(ipv4.Payload[2:])
	if ipv4.Payload[13]&0b00010000 != 0 {
		tcp.ACK = true
	}
	if ipv4.Payload[13]&0b00001000 != 0 {
		tcp.PSH = true
	}
	if ipv4.Payload[13]&0b00000010 != 0 {
		tcp.SYN = true
	}
	if ipv4.Payload[13]&0b00000001 != 0 {
		tcp.FIN = true
	}
	tcp.Payload = ipv4.Payload[21:]
	return &tcp
}

type UDP struct {
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

func NewUDPFromIPv4(ipv4 *IPv4) *UDP {
	var udp UDP
	udp.SrcPort = binary.BigEndian.Uint16(ipv4.Payload)
	udp.DstPort = binary.BigEndian.Uint16(ipv4.Payload[2:])
	udp.Payload = ipv4.Payload[8:]
	return &udp
}
