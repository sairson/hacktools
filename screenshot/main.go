package main

import (
	"fmt"
	"github.com/kbinani/screenshot"
	"image/png"
	"os"
	"strings"
	"time"
)

func main() {
	timeStr := strings.ReplaceAll(time.Now().Format("2006-01-02-15-04-05"),"-","_")
	n := screenshot.NumActiveDisplays()
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}
		fileName := fmt.Sprintf("%s.png",timeStr)
		file, _ := os.Create(fileName)
		defer file.Close()
		png.Encode(file, img)
		fmt.Printf("#%d : %v \"%s\"\n", i, bounds, fileName)
	}
}