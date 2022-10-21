package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var cliFilter = flag.Bool("f", false, "过滤连接")
var cliReport = flag.Bool("r", false, "生成报告")
var cliDir = flag.String("dir", "", "指定目录")
var cliVip = flag.String("vip", "", "指定Vip")

func main() {
	flag.Parse()
	vip := GetVip(cliVip)

	if *cliFilter {
		dir, err := os.Open(*cliDir)
		if err != nil {
			log.Fatal("Can not open dir ", *cliDir, err)
		}
		filenames, _ := dir.Readdirnames(0)
		for i := 0; i < len(filenames); i++ {
			filenames[i] = *cliDir + "/" + filenames[i]
		}

		list := make(ConnectionList)
		for _, filename := range filenames {
			if strings.HasSuffix(filename, ".pcap") {
				ps := ReadPcapData(filename)
				list.AddConnection(ps)
			}
		}
		for k, v := range list {
			lltime := v.end_time.Sub(v.begin_time)
			if lltime > 29*time.Second && lltime < 31*time.Second && (k.SrcIP == vip || k.DstIP == vip) {
				fmt.Println("host", k.SrcIP.String(), "and port", k.SrcPort, "---> host", k.DstIP.String(), "and port", k.DstPort, v.packet_num)
			}
		}
	}
	if *cliReport {
		fmt.Println(vip.String())
		Report(*cliDir, vip)
		// GetReport(flag.Arg(0), "test3", vip, IN)
	}
}

func GetVip(str *string) IP {
	strs := strings.Split(*str, ".")
	var vip IP
	for i, v := range strs {
		v, err := strconv.Atoi(v)
		if err != nil {
			log.Fatal("Cannot convert vip\n", err)
		}
		vip[i] = byte(v)
	}
	return vip
}
