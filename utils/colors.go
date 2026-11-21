package utils

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func HexToRGB(hex string) (float64, float64, float64, error) {
	hex = strings.TrimPrefix(hex, "#")

	if len(hex) != 6 {
		return 0, 0, 0, fmt.Errorf("invalid hex color: %s", hex)
	}

	r, err := strconv.ParseInt(hex[0:2], 16, 64)
	if err != nil {
		return 0, 0, 0, err
	}

	g, err := strconv.ParseInt(hex[2:4], 16, 64)
	if err != nil {
		return 0, 0, 0, err
	}

	b, err := strconv.ParseInt(hex[4:6], 16, 64)
	if err != nil {
		return 0, 0, 0, err
	}

	return float64(r) / 255,
		float64(g) / 255,
		float64(b) / 255, nil
}

func Luminance(v float64) float64 {
	if v <= 0.04045 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

func GetTextColorToBackgroundColor(hex string) (string, error) {
	r, g, b, err := HexToRGB(hex)
	if err != nil {
		return "#000000", err
	}

	l := 0.2126*Luminance(r) +
		0.7152*Luminance(g) +
		0.0722*Luminance(b)

	blackContrast := (l + 0.05) / 0.05
	whiteContrast := 1.05 / (l + 0.05)

	if blackContrast >= whiteContrast {
		return "#000000", nil
	}

	return "#FFFFFF", nil
}
