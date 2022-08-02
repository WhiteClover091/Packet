package main

import (
	"fmt"
)

func main() {
	packetSource := ReadPcapData("2022-08-02-11-04-45-11.122.30.47.pcap")
	// fmt.Println(packet.pcaprec_hdr_s)
	// fmt.Println(packet.CaptureTime())
	i := 0
	for packet, _ := packetSource.NextPacket(); i < 100; packet, _ = packetSource.NextPacket() {
		fmt.Println(i, " ", packet.CaptureTime())
		i++
	}
}
