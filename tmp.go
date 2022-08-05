package main

// type Flow struct {
// 	DstAddress IP
// 	SrcAddress IP
// }

// func main() {
// 	packetSource := ReadPcapData("2022-08-02-11-04-45-11.122.30.101.pcap")
// 	list := make(map[IP]int)
// 	i := 0
// 	for packet, err := packetSource.NextPacket(); err == nil; packet, err = packetSource.NextPacket() {
// 		ethernet := NewEthernet(packet)
// 		ipv4 := NewIPv4(ethernet)
// 		if ipv4.NextLayerType().layerNumber != 2 {
// 			continue
// 		}
// 		ip := IP([4]byte{11, 122, 40, 57})
// 		if ipv4.DstAddress != ip && ipv4.SrcAddress != ip {
// 			fmt.Println(i, ":")
// 			PacketDump(packet)
// 			fmt.Println()
// 			i++
// 		}

// 	}
// 	fmt.Println(len(list))
// 	for k, v := range list {
// 		fmt.Printf("times: %v IP: %v\n", v, k)
// 	}
// }
