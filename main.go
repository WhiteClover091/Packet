package main

import (
	"flag"
	"fmt"
)

var cliPacket = flag.Bool("p", false, "解析报文")
var cliConnection = flag.Bool("c", false, "输出连接五元组")
var cliStat = flag.Bool("s", false, "输出统计结果")
var cliDraw = flag.Bool("d", false, "绘图")

func main() {
	flag.Parse()
	if *cliPacket {
		for _, fliename := range flag.Args() {
			PacketSource := ReadPcapData(fliename)
			for packet, err := PacketSource.NextPacket(); err == nil; packet, err = PacketSource.NextPacket() {
				PacketDump(packet)
				fmt.Println()
			}
		}
	}

	list := make(ConnectionList)
	for _, filename := range flag.Args() {
		packetSource := ReadPcapData(filename)
		list.AddConnection(packetSource)
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
		// DrawScatter(list, 0, 500, "test3.png")
		DrawPacketNumberHist(list, 0, 30, 30, "test.png")
		DrawLiveTimeHist(list, 1, 28, 10, "test2.png")
		DrawBoxplot(list, 1, 50, "test5.png")
		// DrawAvgLiveTime(list, 1, 50)
	}
}
