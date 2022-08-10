package main

import (
	"fmt"
	"log"
	"math"
	"time"

	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/palette"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

type offsetUnitGrid struct {
	XOffset, YOffset float64

	Data mat.Matrix
}

func (g offsetUnitGrid) Dims() (c, r int)   { r, c = g.Data.Dims(); return c, r }
func (g offsetUnitGrid) Z(c, r int) float64 { return g.Data.At(r, c) }
func (g offsetUnitGrid) X(c int) float64 {
	_, n := g.Data.Dims()
	if c < 0 || c >= n {
		panic("column index out of range")
	}
	return float64(c) + g.XOffset
}
func (g offsetUnitGrid) Y(r int) float64 {
	m, _ := g.Data.Dims()
	if r < 0 || r >= m {
		panic("row index out of range")
	}
	return float64(r) + g.YOffset
}

type integerTicks struct{}

func (integerTicks) Ticks(min, max float64) []plot.Tick {
	var t []plot.Tick
	for i := math.Trunc(min); i <= max; i++ {
		t = append(t, plot.Tick{Value: i, Label: fmt.Sprint(i)})
	}
	return t
}

func GetDensityMatrix(list ConnectionList, pmin int, pmax int, tmin int, tmax int) mat.Matrix {
	s := make([]float64, (pmax-pmin+1)*(tmax-tmin+1))
	for _, v := range list {
		p := v.packet_num
		t := v.end_time.Sub(v.begin_time)
		for i := pmin; i <= pmax; i++ {
			for j := tmin; j <= tmax; j++ {
				if p == i && t >= time.Duration(j)*time.Second && t < time.Duration(j+1)*(time.Second) {
					s[(j-tmin)*(pmax-pmin+1)+i-pmin] += 1
				}
			}
		}
	}
	data := mat.NewDense(tmax-tmin+1, pmax-pmin+1, s)
	return data
}

func HeatMap(data mat.Matrix, xOffset, yOffset float64) {
	m := offsetUnitGrid{
		XOffset: xOffset,
		YOffset: yOffset,
		Data:    data}

	pal := palette.Heat(12, 1)
	plt := plot.New()

	raster := plotter.NewHeatMap(&m, pal)
	raster.Rasterized = true
	plt.Add(raster)

	if err := plt.Save(10*vg.Inch, 10*vg.Inch, "1.png"); err != nil {
		log.Fatal(err)
	}
}
