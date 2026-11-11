// csix-phish: pemeriksa URL phishing offline (heuristik, tanpa jaringan).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/siedysoes/csix-phish/internal/phish"
	"github.com/siedysoes/csix-phish/internal/ui"
)

const version = "0.1.0"

func main() {
	var (
		jsonOut     bool
		threshold   int
		noColor     bool
		showVersion bool
	)
	flag.BoolVar(&jsonOut, "json", false, "output JSON")
	flag.IntVar(&threshold, "threshold", 40, "skor minimal yang dianggap berbahaya (exit 1)")
	flag.BoolVar(&noColor, "no-color", false, "matikan warna output")
	flag.BoolVar(&showVersion, "version", false, "tampilkan versi")
	flag.Parse()

	if showVersion {
		fmt.Println("csix-phish v" + version)
		return
	}
	if !noColor {
		ui.Setup()
	}

	urls := flag.Args()
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "penggunaan: csix-phish <url> [url...]   (contoh: csix-phish https://paypa1.com)")
		fmt.Fprintln(os.Stderr, "           csix-phish --json <url>")
		os.Exit(2)
	}

	var results []phish.Result
	highRisk := false
	for _, raw := range urls {
		res, err := phish.Check(raw)
		if err != nil {
			warn("URL tidak valid: " + raw)
			continue
		}
		results = append(results, res)
		if res.Score >= threshold {
			highRisk = true
		}
	}

	if jsonOut {
		if results == nil {
			results = []phish.Result{}
		}
		b, err := json.MarshalIndent(map[string]any{
			"tool":      "csix-phish",
			"version":   version,
			"threshold": threshold,
			"results":   results,
		}, "", "  ")
		if err != nil {
			fatal(err.Error())
		}
		fmt.Println(string(b))
	} else {
		for _, res := range results {
			printResult(res)
			fmt.Println()
		}
		fmt.Println(ui.Wrap(ui.Gray, "analisis 100% offline — URL tidak pernah dikirim ke server mana pun"))
	}

	if highRisk {
		os.Exit(1)
	}
}

func printResult(res phish.Result) {
	levelColor := ui.Green
	switch res.Level {
	case phish.LevelSuspicious:
		levelColor = ui.Yellow
	case phish.LevelDangerous:
		levelColor = ui.Red
	case phish.LevelCritical:
		levelColor = ui.Red
	}

	fmt.Println(ui.Wrap(ui.Bold, "▸ "+res.URL))
	fmt.Printf("  %-8s %s\n", "Host", ui.Wrap(ui.Gray, res.Host))
	if res.Domain != res.Host {
		fmt.Printf("  %-8s %s\n", "Domain", ui.Wrap(ui.Gray, res.Domain))
	}

	bar := bar(res.Score)
	fmt.Printf("  %-8s %d/100  %s  %s\n", "Skor", res.Score, bar, ui.Wrap(levelColor, res.Level))

	if len(res.Signals) > 0 {
		fmt.Println()
		fmt.Println(ui.Wrap(ui.Gray, "  Sinyal risiko:"))
		for _, s := range res.Signals {
			fmt.Printf("   %s [%s] %s\n", ui.Wrap(ui.Gray, "•"), ui.Wrap(ui.Yellow, fmt.Sprintf("%2d", s.Weight)), s.Desc)
		}
	}
}

func bar(score int) string {
	filled := score / 5
	if filled > 20 {
		filled = 20
	}
	return ui.Wrap(ui.Gray, strings.Repeat("█", filled)+strings.Repeat("░", 20-filled))
}

func warn(msg string) {
	fmt.Fprintln(os.Stderr, ui.Wrap(ui.Yellow, "peringatan: ")+msg)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, ui.Wrap(ui.Red, "error: ")+msg)
	os.Exit(2)
}
