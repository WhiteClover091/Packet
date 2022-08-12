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
var cliFilteredPacket = flag.Bool("fp", false, "过滤包")
var cliFilteredConnection = flag.Bool("fc", false, "过滤连接")

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
		DrawScatter(list, 0, 40, "scatter.png")
		DrawPacketNumberHist(list, 1, 40, 45, "phist.png")
		DrawLiveTimeHist(list, 1, 250, 2, "thist.png")
		DrawBoxplot(list, 1, 40, "box.png")
	}

	if *cliFilteredPacket {
		ps := ReadPcapData(flag.Arg(0))
		FilterPacket(ps, ALLIP, ALLIP, ALLPORT, ALLPORT)
	}
	if *cliFilteredConnection {

	}
}

type ipAndPort struct {
	ip   IP
	port int
}
