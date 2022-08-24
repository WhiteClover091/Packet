package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

const (
	IN  = 1
	OUT = 2
)

func GetReport(filenames []string, reportname string, vip IP, direction int) {
	f, err := os.Create(reportname + ".md")
	if err != nil {
		log.Fatal(err)
	}
	list := make(ConnectionList)
	for _, filename := range filenames {
		ps := ReadPcapData(filename)
		list.AddConnection(ps)
	}
	if direction == IN {
		list = FilterDstIP(list, vip)
	} else if direction == OUT {
		list = FilterSrcIP(list, vip)
	}

	f.Write([]byte("# " + reportname + "文件抓包数据统计\n"))
	TotalStat(f, list, direction)
	// Picture(f, list, reportname, filename)

	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func TotalStat(f *os.File, list ConnectionList, direction int) {
	packet_num, tcp_num, udp_num := 0, 0, 0
	total_bytes, tcp_bytes, udp_bytes := 0, 0, 0
	conn_num, tcp_conn_num, udp_conn_num := 0, 0, 0
	iptable := make(map[IP]int)
	begintime, tcp_begintime, udp_begintime := time.Now(), time.Now(), time.Now()
	var endtime, tcp_endtime, udp_endtime time.Time
	cnt := 0

	for k, v := range list {
		update(&v, &packet_num, &total_bytes, &conn_num, &begintime, &endtime)
		if k.layer == LayerTCP {
			update(&v, &tcp_num, &tcp_bytes, &tcp_conn_num, &tcp_begintime, &tcp_endtime)
		} else if k.layer == LayerUDP {
			update(&v, &udp_num, &udp_bytes, &udp_conn_num, &udp_begintime, &udp_endtime)
		}
		if direction == IN {
			iptable[k.SrcIP]++
		} else if direction == OUT {
			iptable[k.DstIP]++
		}
		if v.SYN != 0 && v.FIN != 0 {
			cnt++
		}
	}

	f.Write([]byte("总体:\n"))
	WriteFunc(f, begintime, endtime, packet_num, total_bytes, conn_num)
	f.Write([]byte("TCP:\n"))
	WriteFunc(f, tcp_begintime, tcp_endtime, tcp_num, tcp_bytes, tcp_conn_num)
	f.Write([]byte("UDP:\n"))
	WriteFunc(f, udp_begintime, udp_endtime, udp_num, udp_bytes, udp_conn_num)

	iplist := sortMapByValue(iptable)
	f.Write([]byte("出现次数最多的ip及占比:\n"))
	for i := 0; i < 5 && i < iplist.Len(); i++ {
		msg := fmt.Sprintf("- %v: %v 占比：%.2f%%\n", iplist[i].Key.String(), iplist[i].Value, float64(iplist[i].Value)/float64(conn_num)*100)
		f.Write([]byte(msg))
	}
	f.Write([]byte("\n"))

	msg := fmt.Sprintf("%v 连接至少完成了一次三次握手四次挥手， 占比%.2f%%\n\n", cnt, float64(cnt)/float64(conn_num)*100)
	f.Write([]byte(msg))
}

func WriteFunc(f *os.File, begin, end time.Time, packet_num, total_bytes, conn_num int) {
	if packet_num == 0 {
		f.Write([]byte("无报文\n\n"))
		return
	}

	total_bytes_MB := float64(total_bytes) / 1024 / 1024
	msg := fmt.Sprintf("抓包开始于%v, 结束于%v, 持续时间%v\n", begin, end, end.Sub(begin))
	f.Write([]byte(msg))
	msg = fmt.Sprintf("- 连接数：%v\n- 报文数: %v\n- 总字节数： %.2fMB\n", conn_num, packet_num, total_bytes_MB)
	f.Write([]byte(msg))
	msg = fmt.Sprintf("- 带宽： %.2f MB/s\n- 连接密度： \n\t- 总字节数/连接数：%.2fMB\n\t- 报文数/连接数：%.2f\n",
		float64(total_bytes_MB)/float64(end.Sub(begin))*float64(time.Second),
		float64(total_bytes_MB)/float64(conn_num),
		float64(packet_num)/float64(conn_num))
	f.Write([]byte(msg))
	f.Write([]byte("\n"))
}

type IPPair struct {
	Key   IP
	Value int
}

// A slice of Pairs that implements sort.Interface to sort by Value.
type PairList []IPPair

func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

// A function to turn a map into a PairList, then sort and return it.
func sortMapByValue(m map[IP]int) PairList {
	p := make(PairList, len(m))
	i := 0
	for k, v := range m {
		p[i] = IPPair{k, v}
		i++
	}
	sort.Sort(p)
	return p
}

func Picture(f *os.File, list ConnectionList, dirname, filename string) {
	os.Mkdir(dirname, os.ModePerm)

	msg := "## 连接的报文数目和存活时间分布\n"
	f.Write([]byte(msg))

	packet_num := make(plotter.Values, len(list))
	lltime := make(plotter.Values, len(list))
	i := 0
	for _, v := range list {
		packet_num[i] = float64(v.packet_num)
		lltime[i] = float64(v.end_time.Sub(v.begin_time)) / float64(time.Second)
		i++
	}

	msg = "### 散点图\n"
	f.Write([]byte(msg))
	Scatter(f, packet_num, lltime, dirname)
	msg = "### 报文数目分布直方图\n"
	f.Write([]byte(msg))
	PacketHist(f, packet_num, dirname)
	msg = "### 存活时间分布直方图\n"
	f.Write([]byte(msg))
	LiveTimeHist(f, lltime, dirname)
	msg = "### 仅含有一个报文的连接的捕获时间\n"
	f.Write([]byte(msg))
	OnePacketCaptureTimeHist(f, list, dirname, filename)
}
func PacketHist(f *os.File, packet_num plotter.Values, dirname string) {
	p := plot.New()
	h, err := plotter.NewHist(packet_num, 100)
	h.Normalize(100)
	if err != nil {
		log.Fatal(err)
	}
	xmin, xmax, _, _ := h.DataRange()
	h, err = plotter.NewHist(packet_num, int(xmax)-int(xmin))
	if err != nil {
		log.Fatal(err)
	}
	h.Normalize(100)
	_, _, _, ymax := h.DataRange()

	p.Add(h)
	p.Y.Max = ymax + 5
	p.Y.Label.Text = "Connection Percentage/%"
	p.X.Label.Text = "Packet Number"
	p.Title.Text = "Packet Number Distribution Histogram"

	if err := p.Save(10*vg.Inch, 10*vg.Inch, dirname+"/phist1.png"); err != nil {
		log.Fatal(err)
	}
	msg := fmt.Sprintf("![phist1](%v/phist1.png)\n", dirname)
	f.Write([]byte(msg))

	p.X.Max = 100
	if err := p.Save(10*vg.Inch, 10*vg.Inch, dirname+"/phist2.png"); err != nil {
		log.Fatal(err)
	}
	msg = fmt.Sprintf("![phist2](%v/phist2.png)\n", dirname)
	f.Write([]byte(msg))

	msg = "占比超过5%的连接对应的报文数有：\n"
	for _, bin := range h.Bins {
		if bin.Weight >= 5 {
			msg := fmt.Sprintf("- %v个报文的连接占比%.2f%% \n", bin.Min, bin.Weight)
			f.Write([]byte(msg))
		}
	}
}

func LiveTimeHist(f *os.File, lltime plotter.Values, dirname string) {
	p := plot.New()
	h, err := plotter.NewHist(lltime, 100)
	h.Normalize(100)
	if err != nil {
		log.Fatal(err)
	}
	xmin, xmax, _, _ := h.DataRange()
	h, err = plotter.NewHist(lltime, int(xmax)-int(xmin))
	if err != nil {
		log.Fatal(err)
	}
	h.Normalize(100)
	_, _, _, ymax := h.DataRange()

	p.Add(h)
	p.Y.Max = ymax + 5
	p.Y.Label.Text = "Connection Percentage/%"
	p.X.Label.Text = "Live Time/s"
	p.Title.Text = "Live Time Distribution Histogram"

	if err := p.Save(10*vg.Inch, 10*vg.Inch, dirname+"/thist1.png"); err != nil {
		log.Fatal(err)
	}
	msg := fmt.Sprintf("![thist1](%v/thist1.png)\n", dirname)
	f.Write([]byte(msg))

	p.X.Max = 130
	if err := p.Save(10*vg.Inch, 10*vg.Inch, dirname+"/thist2.png"); err != nil {
		log.Fatal(err)
	}
	msg = fmt.Sprintf("![thist2](%v/thist2.png)\n", dirname)
	f.Write([]byte(msg))

	msg = "存活时间超过1%对应的时间段有：\n"
	for _, bin := range h.Bins {
		if bin.Weight >= 1 {
			msg := fmt.Sprintf("- %1.f~%1.fs的连接占比%.2f%% \n", bin.Min, bin.Max, bin.Weight)
			f.Write([]byte(msg))
		}
	}
}

func Scatter(f *os.File, packet_num, lltime plotter.Values, dirname string) {
	pts := make(plotter.XYs, len(packet_num))
	for i := 0; i < len(packet_num); i++ {
		pts[i].X = packet_num[i]
		pts[i].Y = lltime[i]
	}

	p := plot.New()
	s, err := plotter.NewScatter(pts)
	if err != nil {
		log.Fatal(err)
	}
	s.Radius = 1
	p.Add(s)
	p.X.Label.Text = "Packet Number"
	p.Y.Label.Text = "Live Time/s"
	p.Title.Text = "Packet Number - Live Time Scatter"

	if err := p.Save(10*vg.Inch, 10*vg.Inch, dirname+"/scatter.png"); err != nil {
		log.Fatal(err)
	}
	msg := fmt.Sprintf("![scatter](%v/scatter.png)\n", dirname)
	f.Write([]byte(msg))
}

func OnePacketCaptureTimeHist(f *os.File, list ConnectionList, dirname, filename string) {
	var captime plotter.Values
	ps := ReadPcapData(filename)
	p, _ := ps.NextPacket()
	begintime := p.CaptureTime()

	for _, v := range list {
		if v.packet_num == 1 {
			captime = append(captime, float64(v.begin_time.Sub(begintime))/float64(time.Second))
		}
	}

	pic := plot.New()
	h, _ := plotter.NewHist(captime, 100)
	xmin, xmax, _, ymax := h.DataRange()
	h, _ = plotter.NewHist(captime, int(xmax)-int(xmin))

	pic.Add(h)
	pic.Y.Max = ymax + 2
	pic.X.Label.Text = "time/s"
	pic.Y.Label.Text = "Packet Number"
	if err := pic.Save(10*vg.Inch, 10*vg.Inch, dirname+"/1hist.png"); err != nil {
		log.Fatal(err)
	}
	msg := fmt.Sprintf("![1hist](%v/1hist.png)\n", dirname)
	f.Write([]byte(msg))
}
