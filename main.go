package main

func main() {
	packetSource := ReadPcapData("2022-08-02-11-04-45-11.122.30.101.pcap")
	connectionlist := make(ConnectionList)
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
	}

}
