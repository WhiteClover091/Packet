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

var IngoreConnection Connection = Connection{SrcIP: [4]byte{0, 0, 0, 0}, DstIP: [4]byte{0, 0, 0, 0}, DstPort: 0, SrcPort: 0, layer: LayerError}

func (connnection *Connection) ConnectTo() Connection {
	return Connection{SrcIP: connnection.DstIP, DstIP: connnection.SrcIP, SrcPort: connnection.DstPort, DstPort: connnection.SrcPort, layer: connnection.layer}
}
func GetConnection(packet *Packet) Connection {
	var connection Connection
	ethernet := NewEthernet(packet)
	ipv4 := NewIPv4(ethernet)
	connection.DstIP = ipv4.DstAddress
	connection.SrcIP = ipv4.SrcAddress
	if connection.DstIP[0] == 11 && connection.DstIP[1] == 122 && connection.SrcIP[0] == 11 && connection.SrcIP[1] == 122 {
		return IngoreConnection
	}
	if ipv4.NextLayerType() == LayerGRE {
		gre := NewGRE(ipv4)
		ipv4 = NewIPv4(gre)
	} else if ipv4.NextLayerType() == LayerIPv4 {
		ipv4 = NewIPv4(ipv4)
	} else if ipv4.NextLayerType() == LayerICMP {
		return IngoreConnection
	} else if ipv4.NextLayerType() != LayerTCP && ipv4.NextLayerType() != LayerUDP {
		fmt.Println(ipv4.LayerType())
		fmt.Println(ipv4.NextLayerType())
		log.Fatal("unsupported layer")
	}
	if ipv4.DstAddress == ipv4.SrcAddress {
		return IngoreConnection
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
		return IngoreConnection
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

func (list ConnectionList) StatInfo() {
	beginTime, tcpBeginTime, udpBeginTime := time.Now(), time.Now(), time.Now()
	var endTime, tcpEndTime, udpEndTime time.Time
	packetNum, tcpPacketNum, udpPacketNum := 0, 0, 0
	bytes, tcpBytes, udpBytes := 0, 0, 0
	connNum, tcpConnNum, udpConnNum := 0, 0, 0
	for k, v := range list {
		update(&v, &packetNum, &bytes, &connNum, &beginTime, &endTime)
		if k.layer == LayerTCP {
			update(&v, &tcpPacketNum, &tcpBytes, &tcpConnNum, &tcpBeginTime, &tcpEndTime)
		} else if k.layer == LayerUDP {
			update(&v, &udpPacketNum, &udpBytes, &udpConnNum, &udpBeginTime, &udpEndTime)
		}
	}
	fmt.Println("Total:")
	statDump(packetNum, bytes, connNum, beginTime, endTime)
	fmt.Println()
	fmt.Println("TCP:")
	statDump(tcpPacketNum, tcpBytes, tcpConnNum, tcpBeginTime, tcpEndTime)
	fmt.Println()
	fmt.Println("UDP:")
	statDump(udpPacketNum, udpBytes, udpConnNum, udpBeginTime, udpEndTime)
	fmt.Println()
}
func update(v *ConnectionInfo, packetNum *int, bytes *int, connNum *int, beginTime *time.Time, endTime *time.Time) {
	*packetNum += v.packet_num
	*bytes += v.payloadbytes
	*connNum++
	if beginTime.After(v.begin_time) {
		*beginTime = v.begin_time
	}
	if endTime.Before(v.end_time) {
		*endTime = v.end_time
	}
}
func statDump(packetNum int, bytes int, connNum int, beginTime time.Time, endTime time.Time) {
	totalBytes := float64(bytes) / 1024 / 1024
	lastTime := endTime.Sub(beginTime)
	bandWidth := totalBytes / float64(lastTime) * 1e9
	fmt.Println("Begin at ", beginTime, "End at ", endTime, "Last for ", lastTime)
	fmt.Println("Connection Number: ", connNum)
	fmt.Println("Packet Number: ", packetNum)
	fmt.Println("Total Bytes: ", totalBytes, "MB")
	fmt.Println("Bindwidth: ", bandWidth, "MB/s")
	fmt.Println("Connection Desity: ")
	fmt.Println("\t Connection Number / Total Bytes: ", float64(connNum)/totalBytes, "/MB")
	fmt.Println("\t Connection Number / Packet Number: ", float64(connNum)/float64(packetNum))

}
func (list ConnectionList) AddConnection(ps *PacketSource) {
	for packet, err := ps.NextPacket(); err == nil; packet, err = ps.NextPacket() {
		connection := GetConnection(packet)
		if connection == IngoreConnection {
			continue
		}
		_, ok := list[connection]
		if !ok {
			list[connection] = ConnectionInfo{packet_num: 1, begin_time: packet.CaptureTime(), payloadbytes: int(packet.orig_len), end_time: packet.CaptureTime()}
		} else {
			connectioninfo := list[connection]
			connectioninfo.packet_num++
			if packet.CaptureTime().Sub(connectioninfo.begin_time) < 0 {
				connectioninfo.begin_time = packet.CaptureTime()
			} else if packet.CaptureTime().Sub(connectioninfo.end_time) > 0 {
				connectioninfo.end_time = packet.CaptureTime()
			}
			connectioninfo.payloadbytes += int(packet.incl_len)
			list[connection] = connectioninfo
		}
	}
}
