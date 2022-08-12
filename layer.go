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

type LayerType struct {
	layerNumber byte //1 for link layer, 2 for network layer, 3 for transport layer
	protocol    uint16
}

var LayerEthernet LayerType = LayerType{layerNumber: 1, protocol: 0}
var LayerIPv4 LayerType = LayerType{layerNumber: 2, protocol: 0x0800}
var LayerIPv6 LayerType = LayerType{layerNumber: 2, protocol: 0x86DD}
var LayerError LayerType = LayerType{layerNumber: 0, protocol: 0}
var LayerICMP LayerType = LayerType{layerNumber: 3, protocol: 0x01}
var LayerTCP LayerType = LayerType{layerNumber: 3, protocol: 0x06}
var LayerUDP LayerType = LayerType{layerNumber: 3, protocol: 0x11}
var LayerGRE LayerType = LayerType{layerNumber: 2, protocol: 0x2F}
var LayerICMPv6 LayerType = LayerType{layerNumber: 3, protocol: 0x3A}

type Layer interface {
	Payload() []byte
	LayerType() LayerType
	NextLayerType() LayerType
}
type Ethernet struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16
	payload   []byte
}

func (ethernet *Ethernet) Payload() []byte {
	return ethernet.payload
}
func (ethernet *Ethernet) LayerType() LayerType {
	return LayerEthernet
}
func (ethernet *Ethernet) NextLayerType() LayerType {
	switch ethernet.EtherType {
	case 0x0800:
		return LayerIPv4
	case 0x86DD:
		return LayerIPv6
	}
	return LayerError
}
func NewEthernet(p *Packet) *Ethernet {
	var ethernet Ethernet
	ethernet.DstMAC = p.packetData[:6]
	ethernet.SrcMAC = p.packetData[6:12]
	ethernet.EtherType = binary.BigEndian.Uint16(p.packetData[12:])
	ethernet.payload = p.packetData[14:]
	return &ethernet
}

type IP [4]byte

func (ip *IP) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

type IPv4 struct {
	SrcAddress   IP
	DstAddress   IP
	ProtocolType byte
	payload      []byte
}

func (ipv4 *IPv4) Payload() []byte {
	return ipv4.payload
}
func (ipv4 *IPv4) LayerType() LayerType {
	return LayerIPv4
}
func (ipv4 *IPv4) NextLayerType() LayerType {
	switch ipv4.ProtocolType {
	case 0x01:
		return LayerICMP
	case 0x04:
		return LayerIPv4
	case 0x06:
		return LayerTCP
	case 0x11:
		return LayerUDP
	case 0x29:
		return LayerIPv6
	case 0x2F:
		return LayerGRE
	case 0x3A:
		return LayerICMPv6
	}
	return LayerError
}
func NewIPv4(layer Layer) *IPv4 {
	var ipv4 IPv4
	if layer.LayerType() != LayerEthernet && layer.LayerType() != LayerIPv4 && layer.LayerType() != LayerGRE {
		log.Fatal("This is not a Ethernet Frame or a IPv4 Frame")
	}
	frame := layer.Payload()
	for i := 0; i < 4; i++ {
		ipv4.SrcAddress[i] = frame[i+12]
		ipv4.DstAddress[i] = frame[i+16]
	}
	ipv4.ProtocolType = frame[9]
	ipv4.payload = frame[20:]
	return &ipv4
}

type TCP struct {
	SrcPort uint16
	DstPort uint16
	ACK     bool
	PSH     bool
	SYN     bool
	FIN     bool
	NS      bool
	CWR     bool
	ECE     bool
	URG     bool
	RST     bool
	payload []byte
}

func (tcp *TCP) Payload() []byte {
	return tcp.payload
}
func (tcp *TCP) LayerType() LayerType {
	return LayerTCP
}
func (tcp *TCP) NextLayerType() LayerType {
	return LayerError
}
func NewTCP(layer Layer) *TCP {
	var tcp TCP
	if layer.LayerType() != LayerIPv4 {
		log.Fatal("This is not a IPv4 Frame")
	}
	frame := layer.Payload()
	tcp.SrcPort = binary.BigEndian.Uint16(frame)
	tcp.DstPort = binary.BigEndian.Uint16(frame[2:])
	if frame[13]&0b00010000 != 0 {
		tcp.ACK = true
	}
	if frame[13]&0b00001000 != 0 {
		tcp.PSH = true
	}
	if frame[13]&0b00000010 != 0 {
		tcp.SYN = true
	}
	if frame[13]&0b00000001 != 0 {
		tcp.FIN = true
	}
	if frame[12]&0b00000001 != 0 {
		tcp.NS = true
	}
	if frame[13]&0b10000000 != 0 {
		tcp.CWR = true
	}
	if frame[13]&0b01000000 != 0 {
		tcp.ECE = true
	}
	if frame[13]&0b00100000 != 0 {
		tcp.URG = true
	}
	if frame[13]&0b00000100 != 0 {
		tcp.RST = true
	}
	if len(frame) == 20 {
		return &tcp
	}
	tcp.payload = frame[21:]
	return &tcp
}

type UDP struct {
	SrcPort uint16
	DstPort uint16
	payload []byte
}

func (udp *UDP) Payload() []byte {
	return udp.payload
}
func (udp *UDP) LayerType() LayerType {
	return LayerUDP
}
func (udp *UDP) NextLayerType() LayerType {
	return LayerError
}
func NewUDP(layer Layer) *UDP {
	var udp UDP
	if layer.LayerType() != LayerIPv4 {
		log.Fatal("This is not a IPv4 Frame")
	}
	frame := layer.Payload()
	udp.SrcPort = binary.BigEndian.Uint16(frame)
	udp.DstPort = binary.BigEndian.Uint16(frame[2:])
	udp.payload = frame[8:]
	return &udp
}

type GRE struct {
	ProtocalType uint16
	payload      []byte
}

func (gre *GRE) Payload() []byte {
	return gre.payload
}
func (gre *GRE) LayerType() LayerType {
	return LayerGRE
}
func (gre *GRE) NextLayerType() LayerType {
	return LayerIPv4
}
func NewGRE(layer Layer) *GRE {
	var gre GRE
	if layer.LayerType() != LayerIPv4 {
		log.Fatal("This is not a IPv4 Frame")
	}
	frame := layer.Payload()
	gre.ProtocalType = binary.BigEndian.Uint16(frame[2:])
	var offset int = 0
	if frame[0]&0b10000000 != 0 {
		offset = offset + 4
	}
	if frame[0]&0b00100000 != 0 {
		offset = offset + 4
	}
	if frame[0]&0b00010000 != 0 {
		offset = offset + 4
	}
	gre.payload = frame[4+offset:]
	return &gre
}

type ICMP struct {
	Code byte
}

func (icmp *ICMP) Payload() []byte {
	return nil
}

func (icmp *ICMP) LayerType() LayerType {
	return LayerICMP
}
func (icmp *ICMP) NextLayerType() LayerType {
	return LayerError
}

func NewICMP(layer Layer) *ICMP {
	var icmp ICMP
	if layer.LayerType() != LayerIPv4 {
		log.Fatal("This is not a IPv4 Frame")
	}
	frame := layer.Payload()
	icmp.Code = frame[1]
	return &icmp
}

func PacketDump(packet *Packet) {
	fmt.Println(packet.CaptureTime())
	ethernet := NewEthernet(packet)
	fmt.Println("Ethernet:")
	fmt.Printf("DstMAC: %v SrcMAC: %v\n", ethernet.DstMAC, ethernet.SrcMAC)
	var layer Layer = ethernet
	for layer.LayerType().layerNumber != 3 {
		switch layer.NextLayerType() {
		case LayerIPv4:
			layer = NewIPv4(layer)
			fmt.Println("IPv4:")
			fmt.Printf("DstAddr: %v SrcAddr: %v Protocal: %04x\n", layer.(*IPv4).DstAddress.String(), layer.(*IPv4).SrcAddress.String(), layer.(*IPv4).ProtocolType)
		case LayerGRE:
			layer = NewGRE(layer)
			fmt.Println("GRE:")
			fmt.Printf("Protocol: %04x\n", layer.(*GRE).ProtocalType)
		case LayerICMP:
			layer = NewICMP(layer)
			fmt.Println("ICMP:")
			fmt.Printf("Code: %d\n", layer.(*ICMP).Code)
		case LayerTCP:
			layer = NewTCP(layer)
			fmt.Println("TCP:")
			fmt.Printf("DstPort: %v SrcPort: %v\n", layer.(*TCP).DstPort, layer.(*TCP).SrcPort)
		case LayerUDP:
			layer = NewUDP(layer)
			fmt.Println("UDP:")
			fmt.Printf("DstPort: %v SrcPort: %v\n", layer.(*UDP).DstPort, layer.(*UDP).SrcPort)
		case LayerError:
			log.Fatal("Unsupported layer")
		}
	}
}

func Hex(b []byte) {
	for _, v := range b {
		fmt.Printf("%02x ", v)
	}
	fmt.Println()
}
