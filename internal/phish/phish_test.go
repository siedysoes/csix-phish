package phish

import "testing"

func TestCheckLegitURLs(t *testing.T) {
	urls := []string{
		"https://google.com",
		"https://github.com/siedysoes",
		"https://tokopedia.com",
		"http://localhost:8080",
	}
	for _, raw := range urls {
		res, err := Check(raw)
		if err != nil {
			t.Errorf("%s: error %v", raw, err)
			continue
		}
		if res.Level != LevelLow {
			t.Errorf("%s: level = %s (score %d), seharusnya LOW", raw, res.Level, res.Score)
		}
	}
}

func TestCheckTyposquat(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		minS int
	}{
		{"http://paypa1-secure.com/login", LevelDangerous, 40},
		{"http://g00gle.com/verify", LevelDangerous, 40},
		{"https://paypal.com.security-check.net/signin", LevelDangerous, 40},
	}
	for _, c := range cases {
		res, err := Check(c.raw)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if res.Level != c.want {
			t.Errorf("%s: level = %s (score %d), diharapkan %s", c.raw, res.Level, res.Score, c.want)
		}
		if res.Score < c.minS {
			t.Errorf("%s: score = %d, minimal %d", c.raw, res.Score, c.minS)
		}
	}
}

func TestCheckOtherSignals(t *testing.T) {
	cases := []struct {
		raw    string
		wantID string
	}{
		{"http://192.168.1.1:8080/admin", "private-ip"},
		{"http://2130706433/login", "numeric-host"},
		{"https://bit.ly/3xYzAb", "shortener"},
		{"http://user:pass@evil.example/", "userinfo"},
		{"https://xn--80ak6aa92e.com/", "punycode"},
		{"http://totally-random-name.xyz/", "risky-tld"},
	}
	for _, c := range cases {
		res, err := Check(c.raw)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		found := false
		for _, s := range res.Signals {
			if s.ID == c.wantID {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: sinyal %q tidak ditemukan (signals: %+v)", c.raw, c.wantID, res.Signals)
		}
	}
}

func TestCheckKeywordWeightCap(t *testing.T) {
	// path dengan banyak kata kunci — bobot total tak boleh melebihi 24
	res, err := Check("http://evil-site.com/secure-login-verify-account-bank-update/")
	if err != nil {
		t.Fatal(err)
	}
	kwTotal := 0
	for _, s := range res.Signals {
		if s.ID == "suspicious-keywords" {
			kwTotal = s.Weight
		}
	}
	if kwTotal == 0 || kwTotal > 24 {
		t.Errorf("bobot keywords = %d (harus 1..24)", kwTotal)
	}
}

func TestCheckInvalid(t *testing.T) {
	if _, err := Check("://:"); err == nil {
		t.Error("URL rusak seharusnya mengembalikan error")
	}
}

func TestLevenshtein(t *testing.T) {
	if got := levenshtein("paypal", "paypa1"); got != 1 {
		t.Errorf("levenshtein(paypal, paypa1) = %d, harus 1", got)
	}
	if got := levenshtein("google", "google"); got != 0 {
		t.Errorf("levenshtein identik = %d, harus 0", got)
	}
}
