package main

import (
	"fmt"
)

func main() {
	connectionlist := make(ConnectionList)
	filelist := []string{"2022-08-02-11-04-45-11.122.30.6.pcap", "2022-08-02-11-04-45-11.122.30.47.pcap", "2022-08-02-11-04-45-11.122.30.52.pcap", "2022-08-02-11-04-45-11.122.30.101.pcap"}
	for _, filename := range filelist {
		packetSource := ReadPcapData(filename)
		connectionlist.AddConnection(packetSource)
	}
	VIP := IP([4]byte{140, 207, 118, 222})
	LDIP := IP([4]byte{11, 122, 40, 57})
	cnt := 0
	tmplist := make(map[IP]int)
	for k, v := range connectionlist {
		if (k.DstIP != VIP && k.SrcIP != VIP) && (k.DstIP != LDIP && k.SrcIP != LDIP) {
			cnt += v.packet_num
			tmplist[k.DstIP] += v.packet_num
			tmplist[k.SrcIP] += v.packet_num
		}
	}
	for k, v := range tmplist {
		fmt.Printf("IP: %v times:%v\n", k.String(), v)
	}
	fmt.Println(cnt)
}
