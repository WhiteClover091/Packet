package main

import (
	"fmt"
	"log"
	"time"
)

type Connection struct {
	SrcIP   IP
	DstIP   IP
	SrcPort uint16
	DstPort uint16
	layer   LayerType
}

var ICMPConnection Connection = Connection{SrcIP: [4]byte{0, 0, 0, 0}, DstIP: [4]byte{0, 0, 0, 0}, DstPort: 0, SrcPort: 0, layer: LayerICMP}

func (connnection *Connection) ConnectTo() Connection {
	return Connection{SrcIP: connnection.DstIP, DstIP: connnection.SrcIP, SrcPort: connnection.DstPort, DstPort: connnection.SrcPort, layer: connnection.layer}
}
func GetConnection(packet *Packet) Connection {
	var connection Connection
	ethernet := NewEthernet(packet)
	ipv4 := NewIPv4(ethernet)
	connection.DstIP = ipv4.DstAddress
	connection.SrcIP = ipv4.SrcAddress
	if ipv4.NextLayerType() == LayerGRE {
		gre := NewGRE(ipv4)
		ipv4 = NewIPv4(gre)
	} else if ipv4.NextLayerType() == LayerIPv4 {
		ipv4 = NewIPv4(ipv4)
	} else if ipv4.NextLayerType() == LayerICMP {
		return ICMPConnection
	} else if ipv4.NextLayerType() != LayerTCP && ipv4.NextLayerType() != LayerUDP {
		fmt.Println(ipv4.LayerType())
		fmt.Println(ipv4.NextLayerType())
		log.Fatal("unsupported layer")
	}
	connection.layer = ipv4.NextLayerType()
	if connection.layer == LayerUDP {
		udp := NewUDP(ipv4)
		connection.DstPort = udp.DstPort
		connection.SrcPort = udp.SrcPort
	} else if connection.layer == LayerTCP {
		tcp := NewTCP(ipv4)
		connection.DstPort = tcp.DstPort
		connection.SrcPort = tcp.SrcPort
	} else if connection.layer == LayerICMP {
		return ICMPConnection
	}
	return connection
}

type ConnectionInfo struct {
	packet_num   int
	begin_time   time.Time
	end_time     time.Time
	payloadbytes int
}

type ConnectionList map[Connection]ConnectionInfo

func (list ConnectionList) filter(packet_num int, livetime time.Duration) ConnectionList {
	filteredList := make(ConnectionList)
	for k, v := range list {
		if v.packet_num >= packet_num && v.end_time.Sub(v.begin_time) >= livetime {
			filteredList[k] = v
		}
	}
	return filteredList
}
func (list ConnectionList) totalPacket() int {
	cnt := 0
	for _, v := range list {
		cnt += v.packet_num
	}
	return cnt
}
func (list ConnectionList) totalBytes() int {
	cnt := 0
	for _, v := range list {
		cnt += v.payloadbytes
	}
	return cnt
}

func (list ConnectionList) MaxPacketNumber() int {
	max := 0
	for _, v := range list {
		if v.packet_num > max {
			max = v.packet_num
		}
	}
	return max
}

func (list ConnectionList) MaxLiveTime() time.Duration {
	var d time.Duration
	for _, v := range list {
		if v.end_time.Sub(v.begin_time) > d {
			d = v.end_time.Sub(v.begin_time)
		}
	}
	return d
}
