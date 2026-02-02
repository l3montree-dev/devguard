package shared_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
)

func TestSortQuery(t *testing.T) {

	t.Run("should return a valid SQL query", func(t *testing.T) {
		q := shared.SortQuery{
			Field:    "single",
			Operator: "asc",
		}

		sql := q.SQL()

		assert.Equal(t, `"single" asc`, sql)
	})
}

func TestGetBadgeSVG(t *testing.T) {
	t.Run("should increase width for double-digit values with multiple badges", func(t *testing.T) {
		// Use multiple values to test dynamic boxWidth calculation
		// (single value always uses fixed boxWidth=60)
		singleDigitValues := []shared.BadgeValues{
			{Key: "C", Value: 5, Color: "#e05d44"},
			{Key: "H", Value: 3, Color: "#fe7d37"},
		}
		doubleDigitValues := []shared.BadgeValues{
			{Key: "C", Value: 55, Color: "#e05d44"},
			{Key: "H", Value: 33, Color: "#fe7d37"},
		}
		tripleDigitValues := []shared.BadgeValues{
			{Key: "C", Value: 555, Color: "#e05d44"},
			{Key: "H", Value: 333, Color: "#fe7d37"},
		}

		svgSingle := shared.GetBadgeSVG("test", singleDigitValues)
		svgDouble := shared.GetBadgeSVG("test", doubleDigitValues)
		svgTriple := shared.GetBadgeSVG("test", tripleDigitValues)

		// Extract width from SVG
		widthRegex := regexp.MustCompile(`width="(\d+)"`)

		singleMatch := widthRegex.FindStringSubmatch(svgSingle)
		doubleMatch := widthRegex.FindStringSubmatch(svgDouble)
		tripleMatch := widthRegex.FindStringSubmatch(svgTriple)

		assert.NotEmpty(t, singleMatch, "should find width in single-digit SVG")
		assert.NotEmpty(t, doubleMatch, "should find width in double-digit SVG")
		assert.NotEmpty(t, tripleMatch, "should find width in triple-digit SVG")

		singleWidth, _ := strconv.Atoi(singleMatch[1])
		doubleWidth, _ := strconv.Atoi(doubleMatch[1])
		tripleWidth, _ := strconv.Atoi(tripleMatch[1])

		assert.Greater(t, doubleWidth, singleWidth, "double-digit badge should be wider than single-digit")
		assert.Greater(t, tripleWidth, doubleWidth, "triple-digit badge should be wider than double-digit")
	})

	t.Run("should center text elements with text-anchor middle", func(t *testing.T) {
		values := []shared.BadgeValues{
			{Key: "C", Value: 10, Color: "#e05d44"},
			{Key: "H", Value: 5, Color: "#fe7d37"},
		}

		svg := shared.GetBadgeSVG("test", values)

		// All value text elements should have text-anchor="middle"
		assert.Contains(t, svg, `text-anchor="middle"`, "text elements should be centered")

		// Count occurrences - should have one for each value
		count := strings.Count(svg, `text-anchor="middle"`)
		assert.Equal(t, len(values), count, "should have text-anchor for each value")
	})

	t.Run("should use fractional x position for precise centering", func(t *testing.T) {
		values := []shared.BadgeValues{
			{Key: "C", Value: 55, Color: "#e05d44"}, // 2 digits = boxWidth 35, center at 17.5
		}

		svg := shared.GetBadgeSVG("test", values)

		// Check that x position contains decimal point (fractional value)
		xPosRegex := regexp.MustCompile(`<text x="(\d+\.?\d*)" y="14" text-anchor="middle">`)
		matches := xPosRegex.FindAllStringSubmatch(svg, -1)

		assert.NotEmpty(t, matches, "should find text elements with x positions")

		// For boxWidth=35, center should be at labelWidth(40) + 35/2 = 57.5
		for _, match := range matches {
			xPos := match[1]
			assert.Contains(t, xPos, ".", "x position should be fractional for precise centering")
		}
	})

	t.Run("should show only key for single value badge", func(t *testing.T) {
		values := []shared.BadgeValues{
			{Key: "OK", Value: 0, Color: "#4c1"},
		}

		svg := shared.GetBadgeSVG("test", values)

		// Single value should show only the key, not "OK:0"
		assert.Contains(t, svg, ">OK</text>", "single value badge should show only the key")
		assert.NotContains(t, svg, "OK:0", "single value badge should not show key:value format")
	})

	t.Run("should show key:value for multiple values", func(t *testing.T) {
		values := []shared.BadgeValues{
			{Key: "C", Value: 3, Color: "#e05d44"},
			{Key: "H", Value: 2, Color: "#fe7d37"},
		}

		svg := shared.GetBadgeSVG("test", values)

		assert.Contains(t, svg, "C:3", "multiple values should show key:value format")
		assert.Contains(t, svg, "H:2", "multiple values should show key:value format")
	})
}
