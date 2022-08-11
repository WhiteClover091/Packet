package main

import (
	"image/color"
	"log"
	"math"
	"time"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"
)

func DrawPacketNumberHist(list ConnectionList, min int, max int, ymax float64, filename string) {
	p := plot.New()
	p.X.Label.Text = "Packet Number"
	p.Y.Label.Text = "Connection Percentage/%"

	var values plotter.Values
	maxv, minv := 0, int((^0)>>1)
	for _, v := range list {
		value := v.packet_num
		if value > maxv {
			maxv = value
		} else if value < minv {
			minv = value
		}
		values = append(values, float64(value))
	}
	h, err := plotter.NewHist(values, maxv-minv+1)
	if err != nil {
		log.Fatal(err)
	}
	h.Normalize(100)
	p.Add(h)
	p.X.Max = float64(max)
	p.X.Min = float64(min)
	p.Y.Max = ymax

	if err := p.Save(10*vg.Inch, 10*vg.Inch, filename); err != nil {
		log.Fatal(err)
	}
}

func DrawLiveTimeHist(list ConnectionList, min int, max int, ymax float64, filename string) {
	p := plot.New()
	p.X.Label.Text = "Live Time/s"
	p.Y.Label.Text = "Connection Percentage/%"

	var values plotter.Values
	maxt := time.Nanosecond
	for _, v := range list {
		lltime := v.end_time.Sub(v.begin_time)
		if lltime > maxt {
			maxt = lltime
		}
		values = append(values, float64(lltime)/float64(time.Second))
	}
	h, err := plotter.NewHist(values, int(math.Ceil(float64(maxt)/float64(time.Second)))+1)
	if err != nil {
		log.Fatal(err)
	}
	h.Normalize(100)
	p.Add(h)
	p.X.Max = float64(max)
	p.X.Min = float64(min)
	p.Y.Max = ymax

	if err := p.Save(10*vg.Inch, 10*vg.Inch, filename); err != nil {
		log.Fatal(err)
	}
}

func DrawScatter(list ConnectionList, pmin int, pmax int, filename string) {
	p := plot.New()
	p.X.Label.Text = "Packet Number"
	p.Y.Label.Text = "Live time/s"

	var pts plotter.XYs
	for _, v := range list {
		if v.packet_num >= pmin && v.packet_num <= pmax {
			var pt plotter.XY
			pt.X = float64(v.packet_num)
			pt.Y = float64(v.end_time.Sub(v.begin_time)) / float64(time.Second)
			pts = append(pts, pt)
		}
	}

	s, err := plotter.NewScatter(pts)
	if err != nil {
		log.Fatal(err)
	}
	s.Radius = 1
	p.Y.Max = 300
	p.Add(s)

	if err := p.Save(10*vg.Inch, 10*vg.Inch, filename); err != nil {
		log.Fatal(err)
	}
}

func DrawBoxplot(list ConnectionList, pmin, pmax int, filename string) {
	p := plot.New()
	p.Title.Text = "Live Time Distribution"
	p.X.Label.Text = "Packet number"
	p.Y.Label.Text = "Live Time/s"
	w := vg.Points(5)

	//box plot
	values := make([]plotter.Values, pmax-pmin+1)
	num := make([]int, pmax-pmin+1)
	totaltime := make([]float64, pmax-pmin+1)
	for _, v := range list {
		if v.packet_num >= pmin && v.packet_num <= pmax {
			d := float64(v.end_time.Sub(v.begin_time)) / float64(time.Second)
			values[v.packet_num-pmin] = append(values[v.packet_num-pmin], d)
			num[v.packet_num-pmin]++
			totaltime[v.packet_num-pmin] += d
		}
	}
	for i := 0; i < pmax-pmin+1; i++ {
		if len(values[i]) != 0 {
			b, err := plotter.NewBoxPlot(w, float64(i+pmin), values[i])
			if err != nil {
				log.Fatal(err)
			}
			b.GlyphStyle.Radius = 0.5
			p.Add(b)
		}
	}

	//line and points
	var pts plotter.XYs
	for i := 0; i < pmax-pmin+1; i++ {
		if num[i] != 0 {
			var pt plotter.XY
			pt.X = float64(pmin + i)
			pt.Y = totaltime[i] / float64(num[i])
			pts = append(pts, pt)
		}
	}
	lpLine, lpPoints, err := plotter.NewLinePoints(pts)
	if err != nil {
		log.Fatal(err)
	}
	lpLine.Color = color.RGBA{B: 255, A: 255}
	lpPoints.Radius = 1.5
	lpPoints.Color = color.RGBA{R: 255, B: 128, A: 255}
	lpPoints.Shape = draw.BoxGlyph{}
	p.Legend.Add("Avg Live Time", lpLine, lpPoints)
	p.Add(lpLine, lpPoints)

	if err := p.Save(10*vg.Inch, 10*vg.Inch, filename); err != nil {
		log.Fatal(err)
	}
}
