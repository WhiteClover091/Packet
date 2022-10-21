package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

func Report(dirname string, vip IP) {
	picdir, in, out := MkRepDir(dirname)
	fmt.Println(picdir)
	defer in.Close()
	defer out.Close()
	in.Write([]byte("# 入流量统计\n"))
	out.Write([]byte("# 出流量统计\n"))

	dir, err := os.Open(dirname)
	if err != nil {
		log.Fatal("cann't open dir ", dirname, "\n", err)
	}
	defer dir.Close()
	filenames, _ := dir.Readdirnames(0)
	for i := 0; i < len(filenames); i++ {
		filenames[i] = dirname + "/" + filenames[i]
	}
	LDlists := GetList(filenames)
	totalStat(in, LDlists, IN, vip)
	picture(in, LDlists, picdir, IN, vip)
	totalStat(out, LDlists, OUT, vip)
	picture(out, LDlists, picdir, OUT, vip)
}

func MkRepDir(datadirname string) (string, *os.File, *os.File) {
	strs := strings.Split(datadirname, "/")
	var rdir string
	if strs[len(strs)-1] != "" {
		rdir = strs[len(strs)-1]
	} else {
		rdir = strs[len(strs)-2]
	}

	rdir = "r" + rdir
	picdir := rdir + "/imag"
	infile := rdir + "/in.md"
	outfile := rdir + "/out.md"
	os.Mkdir(rdir, os.ModePerm)
	os.Mkdir(picdir, os.ModePerm)
	in, _ := os.Create(infile)
	out, _ := os.Create(outfile)
	return picdir, in, out
}

func GetList(filenames []string) []ConnectionList {
	var LDlists []ConnectionList
	list := make(ConnectionList)
	for _, filename := range filenames {
		if strings.HasSuffix(filename, ".pcap") {
			ps := ReadPcapData(filename)
			tmplist := make(ConnectionList)
			tmplist.AddConnection(ps)
			ps2 := ReadPcapData(filename)
			list.AddConnection(ps2)
			LDlists = append(LDlists, tmplist)
		}
	}
	LDlists = append(LDlists, list)
	return LDlists
}

func totalStat(f *os.File, lists []ConnectionList, direction int, vip IP) {
	size := len(lists)
	packet_num, bytes, conn_num, udp_num, connected := make([]int, size), make([]int, size), make([]int, size), make([]int, size), make([]int, size)
	var iptables []map[IP]int
	for i := 0; i < size; i++ {
		iptables = append(iptables, make(map[IP]int))
	}

	for i, list := range lists {
		for k, v := range list {
			if k.layer == LayerUDP {
				udp_num[i]++
				continue
			}
			if direction == IN && k.DstIP == vip {
				packet_num[i] += v.packet_num
				bytes[i] += v.payloadbytes
				conn_num[i]++
				iptables[i][k.SrcIP]++
				if v.SYN != 0 && v.FIN != 0 {
					connected[i]++
				}
			} else if direction == OUT && k.SrcIP == vip {
				packet_num[i] += v.packet_num
				bytes[i] += v.payloadbytes
				conn_num[i]++
				iptables[i][k.DstIP]++
				if v.SYN != 0 && v.FIN != 0 {
					connected[i]++
				}
			}
		}
	}
	conn_num2 := make([]int, 0)
	conn_num2 = append(conn_num2, conn_num...)
	msg := "## 总体统计数据\n**统计数据包含了各个LD和总体的数据, 前面的为LD数据, 最后一个数据为总体数据**\n"
	f.Write([]byte(msg))
	one, MB := make([]int, size), make([]int, size)
	for i := 0; i < size; i++ {
		one[i] = 1
		MB[i] = 1024 * 1024
	}
	msg = "- 连接数:"
	msg += WriteHelper(conn_num, one, "")
	f.Write([]byte(msg))

	msg = "- 报文数:"
	msg += WriteHelper(packet_num, one, "")
	f.Write([]byte(msg))

	msg = "- 总字节数:"
	msg += WriteHelper(bytes, MB, "MB")
	f.Write([]byte(msg))

	msg = "- 连接密度:\n\t- 总字节数/连接数:"
	tmp := make([]int, size)
	for i := 0; i < size; i++ {
		tmp[i] = conn_num[i] * 1024 * 1024
	}
	msg += WriteHelper(bytes, tmp, "MB")
	f.Write([]byte(msg))

	msg = "\t- 报文数/连接数: "
	msg += WriteHelper(packet_num, conn_num, "")
	f.Write([]byte(msg))
	//过滤掉报文数大于100的连接
	for i, list := range lists {
		for k, v := range list {
			if direction == IN && k.DstIP == vip && v.packet_num > 100 {
				packet_num[i] -= v.packet_num
				bytes[i] -= v.payloadbytes
				conn_num[i]--
			} else if direction == OUT && k.SrcIP == vip && v.packet_num > 100 {
				packet_num[i] -= v.packet_num
				bytes[i] -= v.payloadbytes
				conn_num[i]--
			}
		}
	}
	msg = "- 连接密度(过滤掉报文数大于100的连接):\n\t- 总字节数/连接数:"
	msg += WriteHelper(bytes, tmp, "MB")
	f.Write([]byte(msg))

	msg = "\t- 报文数/连接数: "
	msg += WriteHelper(packet_num, conn_num, "")
	f.Write([]byte(msg))

	iplists := make([]PairList, size)
	msg = "- 与vip建立连接的ip有"
	//将含有ip信息的map按出现次数排序
	for i := 0; i < size; i++ {
		iplists[i] = sortMapByValue(iptables[i])
		if i != size-1 {
			msg += fmt.Sprintf("%v/", len(iplists[i]))
		} else {
			msg += fmt.Sprintf("%v个ip, 出现次数前五的ip及占比(ip对应的连接在总连接中的占比)是:\n", len(iplists[i]))
		}
	}
	f.Write([]byte(msg))
	w := func(iplists []PairList, rank int) string {
		msg := "\t- " + strconv.Itoa(rank+1) + ": "
		for i := 0; i < len(iplists); i++ {
			if i == len(iplists)-1 {
				msg += fmt.Sprintf("%15v:**%2.2f%%**\n", iplists[i][rank].Key.String(), 100*float64(iplists[i][rank].Value)/float64(conn_num[i]))
			} else {
				msg += fmt.Sprintf("%15v:**%2.2f%%**/", iplists[i][rank].Key.String(), 100*float64(iplists[i][rank].Value)/float64(conn_num[i]))
			}
		}
		return msg
	}
	for i := 0; i < 5; i++ {
		msg = w(iplists, i)
		f.Write([]byte(msg))
	}

	msg = "\n完成了三次握手四次挥手的连接占比为"
	for i := 0; i < size; i++ {
		connected[i] *= 100 //转化为百分数
	}
	msg += WriteHelper(connected, conn_num2, "%")
	f.Write([]byte(msg))
}

func WriteHelper(arr []int, div []int, str string) string {
	var msg string
	//用于格式化的函数
	f := func(div int, f float64, str string) string {
		var msg string
		if f == math.Floor(f) {
			msg = fmt.Sprintf("%v%v", f, str)
		} else if f >= 0.01 {
			msg = fmt.Sprintf("%.2f%v", f, str)
		} else {
			msg = fmt.Sprintf("%.4f%v", f, str)
		}
		return msg
	}
	for i := 0; i < len(arr); i++ {
		v := float64(arr[i]) / float64(div[i])
		if i == len(arr)-1 {
			msg += f(div[i], v, "")
		} else {
			msg += f(div[i], v, "/")
		}
	}

	msg = msg + str + "\n"
	return msg
}

func picture(f *os.File, lists []ConnectionList, dirname string, direction int, vip IP) {
	msg := "## 连接的报文数目和存活时间分布\n**大图为总体统计结果**\n**不同图的横纵坐标可能不同**\n"
	f.Write([]byte(msg))
	var picdir string
	if direction == IN {
		dirname += "/in"
		picdir = "in/"
	} else if direction == OUT {
		dirname += "/out"
		picdir = "out"
	}
	os.Mkdir(dirname, os.ModePerm)

	//将connectionlist中的packet_num 和 lltimes 转换为plotter.Values
	packet_nums := make([]plotter.Values, len(lists))
	lltimes := make([]plotter.Values, len(lists))
	begintimes := make([]time.Time, len(lists))
	capturetimes := make([]plotter.Values, len(lists))
	for i := 0; i < len(begintimes); i++ {
		begintimes[i] = time.Now()
	}
	for i, list := range lists {
		packet_nums[i] = make(plotter.Values, 0)
		lltimes[i] = make(plotter.Values, 0)
		for k, v := range list {
			if direction == IN && k.DstIP == vip {
				packet_nums[i] = append(packet_nums[i], float64(v.packet_num))
				lltimes[i] = append(lltimes[i], float64(v.end_time.Sub(v.begin_time))/float64(time.Second))
				if begintimes[i].After(v.begin_time) {
					begintimes[i] = v.begin_time
				}
			} else if direction == OUT && k.SrcIP == vip {
				packet_nums[i] = append(packet_nums[i], float64(v.packet_num))
				lltimes[i] = append(lltimes[i], float64(v.end_time.Sub(v.begin_time))/float64(time.Second))
				if begintimes[i].After(v.begin_time) {
					begintimes[i] = v.begin_time
				}
			}
		}
	}
	for i, list := range lists {
		capturetimes[i] = make(plotter.Values, 0)
		for k, v := range list {
			if direction == IN && k.DstIP == vip && v.packet_num == 1 {
				capturetimes[i] = append(capturetimes[i], float64(v.begin_time.Sub(begintimes[i]))/float64(time.Second))
			} else if direction == OUT && k.SrcIP == vip && v.packet_num == 1 {
				capturetimes[i] = append(capturetimes[i], float64(v.begin_time.Sub(begintimes[i]))/float64(time.Second))
			}
		}
	}

	//保存图片，返回值为图片的路径
	save := func(p *plot.Plot, i, size int, str string) []byte {
		if i == size-1 {
			if err := p.Save(10*vg.Inch, 6*vg.Inch, dirname+"/"+str+strconv.Itoa(i)+".png"); err != nil {
				log.Fatal(err)
			}
		} else {
			if err := p.Save(4.9*vg.Inch, 4.9*vg.Inch, dirname+"/"+str+strconv.Itoa(i)+".png"); err != nil {
				log.Fatal(err)
			}
		}
		msg := fmt.Sprintf("![](imag/%v/%v%v.png)", picdir, str, i)
		if i%2 == 1 || i == size-1 {
			msg += "\n"
		}
		return []byte(msg)
	}

	msg = "### 散点图\n"
	f.Write([]byte(msg))
	for i := 0; i < len(packet_nums); i++ {
		p := plot.New()
		p.Add(scatter(packet_nums[i], lltimes[i]))
		p.X.Label.Text = "connection number"
		p.Y.Label.Text = "Live Time / s"
		p.Title.Text = "Scatter"
		f.Write(save(p, i, len(packet_nums), "scatter"))
	}

	msg = "\n### 报文数目分布直方图\n"
	f.Write([]byte(msg))
	hists := make([]*plotter.Histogram, len(packet_nums))
	for i := 0; i < len(packet_nums); i++ {
		p := plot.New()
		h := hist(packet_nums[i])
		h.Normalize(100)
		p.Add(h)
		p.X.Label.Text = "packet number"
		p.Y.Label.Text = "Percentage / %"
		p.Title.Text = "Packet Number Distribution Histogram"
		_, _, _, ymax := h.DataRange()
		p.Y.Max = ymax * 1.05
		f.Write(save(p, i, len(packet_nums), "phist"))
		hists[i] = h
	}
	for i := 0; i < len(packet_nums); i++ {
		p := plot.New()
		p.Add(hists[i])
		p.X.Max = 100
		_, _, _, ymax := hists[i].DataRange()
		p.Y.Max = ymax * 1.05
		f.Write(save(p, i, len(packet_nums), "phist2"))
	}
	for i := 0; i < len(hists); i++ {
		var msg string
		if i != len(hists)-1 {
			msg = fmt.Sprintf("LD%d", i)
		} else {
			msg = "总体数据"
		}
		msg += "报文占比排名前五： "
		sort.Slice(hists[i].Bins, func(i2, j int) bool {
			return hists[i].Bins[i2].Weight > hists[i].Bins[j].Weight
		})
		for j := 0; j < 5; j++ {
			msg += fmt.Sprintf("**%.0f**(%.2f%%),", hists[i].Bins[j].Min, hists[i].Bins[j].Weight)
		}
		f.Write([]byte(msg + "\n"))
	}

	msg = "### 存活时间分布直方图\n"
	f.Write([]byte(msg))
	for i := 0; i < len(lltimes); i++ {
		p := plot.New()
		h := hist(lltimes[i])
		h.Normalize(100)
		p.Add(h)
		p.X.Label.Text = "live time /s"
		p.Y.Label.Text = "Percentage / %"
		p.Title.Text = "Live Time Distribution Histogram"
		_, _, _, ymax := h.DataRange()
		p.Y.Max = ymax * 1.05
		f.Write(save(p, i, len(packet_nums), "thist"))
		hists[i] = h
	}
	for i := 0; i < len(lltimes); i++ {
		var msg string
		if i != len(lltimes)-1 {
			msg = fmt.Sprintf("LD%d", i)
		} else {
			msg = "总体数据"
		}
		msg += "存活时间排名前五： "
		sort.Slice(hists[i].Bins, func(i2, j int) bool {
			return hists[i].Bins[i2].Weight > hists[i].Bins[j].Weight
		})
		for j := 0; j < 5; j++ {
			msg += fmt.Sprintf("**%.0f-%.0fs**,", hists[i].Bins[j].Min, hists[i].Bins[j].Max)
		}
		f.Write([]byte(msg + "\n"))
	}
	msg = "### 仅含有一个报文的连接的捕获时间\n"
	f.Write([]byte(msg))
	for i := 0; i < len(capturetimes); i++ {
		if len(capturetimes[i]) == 0 {
			continue
		}
		p := plot.New()
		p.Add(hist(capturetimes[i]))
		p.X.Label.Text = "Capture Time /s"
		p.Y.Label.Text = "Packet Number"
		f.Write(save(p, i, len(capturetimes), "cap"))
	}
}
func scatter(packet_num, lltime plotter.Values) *plotter.Scatter {
	pts := make(plotter.XYs, len(packet_num))
	for i := 0; i < len(packet_num); i++ {
		pts[i].X = packet_num[i]
		pts[i].Y = lltime[i]
	}

	s, err := plotter.NewScatter(pts)
	if err != nil {
		log.Fatal(err)
	}
	s.Radius = 1
	return s
}
func hist(packet_num plotter.Values) *plotter.Histogram {
	h, err := plotter.NewHist(packet_num, 100)
	if err != nil {
		log.Fatal(err)
	}
	xmin, xmax, _, _ := h.DataRange()
	xmax = math.Ceil(xmax)
	h, err = plotter.NewHist(packet_num, int(xmax)-int(xmin)) // 使得直方图的bin宽度为1
	if err != nil {
		log.Fatal(err)
	}
	return h
}
