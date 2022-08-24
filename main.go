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
var cliReport = flag.Bool("r", false, "生成报告")

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
	if *cliConnection || *cliDraw || *cliStat || *cliFilteredConnection {
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
		vip := IP{10, 53, 216, 112}
		i := 0
		for k, v := range list {
			if k.SrcIP != vip && k.DstIP != vip {
				fmt.Print(i, ":")
				i++
				fmt.Println(k.SrcIP.String(), k.DstIP.String(), v.packet_num)
			}
		}
		// DrawScatter(list, 0, 50000, "draw/scatter.png")
		// DrawPacketNumberHist(list, 0, 100, 35, "draw/phist.png")
		// DrawLiveTimeHist(list, 0, 320, 100, "draw/thist.png")
		// DrawBoxplot(list, 0, 100, "draw/box.png")
	}

	if *cliFilteredPacket {
		ps := ReadPcapData(flag.Arg(0))
		FilterPacket(ps, ALLIP, ALLIP, ALLPORT, ALLPORT)
	}
	if *cliFilteredConnection {
		ip := IP{121, 51, 22, 28}
		FilterConnection(list, ALLNUM, ip, ALLIP, ALLPORT, ALLPORT)
	}
	if *cliReport {
		vip := IP{43, 129, 96, 245}
		GetReport(flag.Args(), "IN:香港-沙田-M4-S1-40G-CAP-IP-QcloudIP漂移-DPDK-SET1的VIP:43.129.96.245", vip, IN)
	}
}

func PrintPayload() {}
