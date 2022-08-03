package main

import (
	"fmt"
)

func main() {
	packetSource := ReadPcapData("2022-08-02-11-04-45-11.122.30.47.pcap")
	// fmt.Println(packet.pcaprec_hdr_s)
	// fmt.Println(packet.CaptureTime())
	i := 0
	for packet, err := packetSource.NextPacket(); i < 10000 && err == nil; packet, err = packetSource.NextPacket() {
		fmt.Println(i, ": ", packet.CaptureTime())
		i++
	}
}
