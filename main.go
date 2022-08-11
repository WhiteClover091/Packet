package main

import (
	"flag"
	"fmt"
	"log"
)

var cliPacket = flag.Bool("p", false, "解析报文")
var cliConnection = flag.Bool("c", false, "输出连接五元组")
var cliStat = flag.Bool("s", false, "输出统计结果")
var cliDraw = flag.Bool("d", false, "绘图")

func main() {
	flag.Parse()
	if *cliPacket {
		i := 0
		for _, fliename := range flag.Args() {
			PacketSource := ReadPcapData(fliename)
			for packet, err := PacketSource.NextPacket(); err == nil; packet, err = PacketSource.NextPacket() {
				fmt.Print(i, ":")
				PacketDump(packet)
				fmt.Println()
				i++
			}
		}
	}

	if len(flag.Args()) == 0 {
		log.Fatal("need file")
	}

	list := make(ConnectionList)
	if *cliConnection || *cliDraw || *cliStat {
		for _, filename := range flag.Args() {
			packetSource := ReadPcapData(filename)
			list.AddConnection(packetSource)
		}
	}

	if *cliConnection {
		for k, v := range list {
			fmt.Printf("SrcIP: %v, DstIP: %v, SrcPort: %v, DstPort: %v ",
				k.SrcIP.String(), k.DstIP.String(), k.SrcPort, k.DstPort)
			if k.layer == LayerTCP {
				fmt.Println("Type: TCP")
			} else if k.layer == LayerUDP {
				fmt.Println("Type: UDP")
			}
			fmt.Printf("begin at %v, end at %v\n", v.begin_time, v.end_time)
			fmt.Printf("packet num: %v, live time %v\n", v.packet_num, v.end_time.Sub(v.begin_time))
			fmt.Println()
		}
	}

	if *cliStat {
		list.StatInfo()
	}

	if *cliDraw {
		VIP := IP([4]byte{140, 207, 118, 222})
		for k, _ := range list {
			if k.DstIP != VIP {
				fmt.Println(k.DstIP)
			}
		}
		// DrawScatter(list, 0, 40, "scatter.png")
		// DrawPacketNumberHist(list, 1, 40, 45, "phist.png")
		// DrawLiveTimeHist(list, 1, 250, 2, "thist.png")
		// DrawBoxplot(list, 1, 40, "box.png")
	}
	// iptable := make(map[byte]int)
	// for _, filename := range flag.Args() {
	// 	PacketSource := ReadPcapData(filename)
	// 	for packet, err := PacketSource.NextPacket(); err == nil; packet, err = PacketSource.NextPacket() {
	// 		ethernet := NewEthernet(packet)
	// 		if ethernet.NextLayerType() != LayerIPv4 {
	// 			log.Fatal("error: not a ipv4 packet")
	// 		}
	// 		ipv4 := NewIPv4(ethernet)
	// 		if ipv4.NextLayerType() == LayerTCP {
	// 			iptable[ipv4.DstAddress[0]]++
	// 			iptable[ipv4.SrcAddress[0]]++
	// 		}
	// 	}
	// }
	// i := 0
	// cnt := 0
	// for k, v := range iptable {
	// 	fmt.Println(i, ": ", k, ".0.0.0", v)
	// 	i++
	// 	if k != 140 {
	// 		cnt += v
	// 	}
	// }
	// fmt.Println(cnt, " ", iptable[140])
}
