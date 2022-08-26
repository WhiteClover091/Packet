package main

import (
	"flag"
	"fmt"
)

var cliDraw = flag.Bool("d", false, "绘图")
var cliFilteredConnection = flag.Bool("fc", false, "过滤连接")
var cliReport = flag.Bool("r", false, "生成报告")

func main() {
	flag.Parse()

	list := make(ConnectionList)

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

	if *cliFilteredConnection {
		ip := IP{121, 51, 22, 28}
		FilterConnection(list, ALLNUM, ip, ALLIP, ALLPORT, ALLPORT)
	}
	if *cliReport {
		vip := IP{1, 116, 149, 115}
		GetReport(flag.Arg(0), "test3", vip, IN)
	}
}

func PrintPayload() {}
