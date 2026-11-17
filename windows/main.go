// VPN Master for Windows v2 — The Master Sahib
//
// Two ways to connect, both free:
//  1. USA mode  — your own free WireGuard config (e.g. Proton VPN Free, US server),
//                 run by the embedded WireGuard engine. Most reliable for US-only sites (Meta Muse).
//                 Fallback with zero setup: VPN Gate servers in the US / Canada.
//  2. Free servers — VPN Gate public relay network (Univ. of Tsukuba), via Windows' built-in
//                 VPN (SSTP, L2TP fallback). No drivers, no account.
package main

import (
	"context"
	"sync/atomic"
	_ "embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
)

// version is set at build time: -ldflags "-X main.version=2.2.0"
var version = "dev"

//go:embed ui/index.html
var indexHTML string

//go:embed snapshot.csv
var snapshotCSV []byte

const (
	connName    = "VPN Master"
	vpnUser     = "vpn"
	vpnPass     = "vpn"
	l2tpPSK     = "vpn"
	vgHost      = "www.vpngate.net"
	userAgent   = "VPNMaster/2.0 (+themastersahib.com)"
	createNoWnd = 0x08000000
)

type Server struct {
	Host     string  `json:"host"`
	IP       string  `json:"ip"`
	Score    int64   `json:"score"`
	Ping     int     `json:"ping"`
	SpeedMb  float64 `json:"speed"`
	Country  string  `json:"country"`
	CC       string  `json:"cc"`
	Sessions int     `json:"sessions"`
}

var (
	w       webview2.WebView
	busy    sync.Mutex
	httpc   = &http.Client{Timeout: 15 * time.Second}
	mode    string // "", "ras", "wg"
	servers []Server
	srvMu   sync.Mutex
)

// ---------------- helpers ----------------

var (
	cancelReq atomic.Bool // set by Disconnect/Cancel; checked by every connect step
	cmdMu     sync.Mutex
	curCancel context.CancelFunc
)

// runT runs a command (no console window) with a hard time limit. Cancel kills it at once.
func runT(limit time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	cmdMu.Lock()
	curCancel = cancel
	cmdMu.Unlock()
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWnd}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = errors.New("timed out")
	}
	return strings.TrimSpace(string(out)), err
}

func run(name string, args ...string) (string, error) { return runT(20*time.Second, name, args...) }

// killCurrent stops whatever connect command is running right now.
func killCurrent() {
	cmdMu.Lock()
	if curCancel != nil {
		curCancel()
	}
	cmdMu.Unlock()
}

func ps(script string) (string, error) {
	u := make([]byte, 0, len(script)*2)
	for _, r := range script {
		u = append(u, byte(r), byte(r>>8))
	}
	return runT(25*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(u))
}

func emit(event string, data interface{}) {
	b, _ := json.Marshal(map[string]interface{}{"event": event, "data": data})
	js := "window.onVpnEvent && window.onVpnEvent(" + string(b) + ")"
	w.Dispatch(func() { w.Eval(js) })
}

// dohResolve resolves a hostname through DNS-over-HTTPS (bypasses ISP DNS blocking).
func dohResolve(host string) (netip.Addr, error) {
	urls := []string{
		"https://1.1.1.1/dns-query?name=" + host + "&type=A",
		"https://8.8.8.8/resolve?name=" + host + "&type=A",
		"https://9.9.9.9:5053/dns-query?name=" + host + "&type=A",
	}
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Accept", "application/dns-json")
		resp, err := httpc.Do(req)
		if err != nil {
			continue
		}
		var r struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			}
		}
		json.NewDecoder(resp.Body).Decode(&r)
		resp.Body.Close()
		for _, a := range r.Answer {
			if a.Type == 1 {
				if ip, err := netip.ParseAddr(a.Data); err == nil {
					return ip, nil
				}
			}
		}
	}
	return netip.Addr{}, errors.New("DoH failed")
}

// ---------------- server list (4 sources, never empty) ----------------

func parseCSV(body []byte) []Server {
	var clean []string
	for _, l := range strings.Split(string(body), "\n") {
		l = strings.TrimRight(l, "\r")
		if l == "" || strings.HasPrefix(l, "*") || strings.HasPrefix(l, "#") {
			continue
		}
		clean = append(clean, l)
	}
	r := csv.NewReader(strings.NewReader(strings.Join(clean, "\n")))
	r.FieldsPerRecord = -1
	rows, _ := r.ReadAll()
	var list []Server
	for _, f := range rows {
		if len(f) < 8 || f[0] == "" || net.ParseIP(f[1]) == nil {
			continue
		}
		score, _ := strconv.ParseInt(f[2], 10, 64)
		ping, _ := strconv.Atoi(f[3])
		speed, _ := strconv.ParseFloat(f[4], 64)
		sess, _ := strconv.Atoi(f[7])
		list = append(list, Server{Host: f[0], IP: f[1], Score: score, Ping: ping, SpeedMb: speed / 1e6,
			Country: f[5], CC: strings.ToLower(f[6]), Sessions: sess})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Score > list[j].Score })
	return list
}

func getURL(u, hostHeader string) ([]byte, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", userAgent)
	if hostHeader != "" {
		req.Host = hostHeader
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func cachePath() string { return filepath.Join(appDir(), "servers.csv") }

func fetchServers() ([]Server, string) {
	// 1) direct
	for _, u := range []string{"http://" + vgHost + "/api/iphone/", "https://" + vgHost + "/api/iphone/"} {
		if b, err := getURL(u, ""); err == nil {
			if l := parseCSV(b); len(l) > 0 {
				os.WriteFile(cachePath(), b, 0o644)
				return l, "live"
			}
		}
	}
	// 2) bypass DNS block: resolve via DNS-over-HTTPS, connect by IP
	if ip, err := dohResolve(vgHost); err == nil {
		if b, err := getURL("http://"+ip.String()+"/api/iphone/", vgHost); err == nil {
			if l := parseCSV(b); len(l) > 0 {
				os.WriteFile(cachePath(), b, 0o644)
				return l, "live"
			}
		}
	}
	// 3) last good list saved on this PC
	if b, err := os.ReadFile(cachePath()); err == nil {
		if l := parseCSV(b); len(l) > 0 {
			return l, "saved"
		}
	}
	// 4) list built into the app
	return parseCSV(snapshotCSV), "built-in"
}

// ---------------- Windows built-in VPN (VPN Gate) ----------------

func removeConn() {
	run("rasdial", connName, "/disconnect")
	ps(fmt.Sprintf(`Remove-VpnConnection -Name '%s' -Force -ErrorAction SilentlyContinue`, connName))
}

func dial() error {
	out, err := runT(25*time.Second, "rasdial", connName, vpnUser, vpnPass)
	if err != nil {
		return errors.New(out)
	}
	return nil
}

func tryVPNGate(s Server) (string, bool) {
	if cancelReq.Load() {
		return "", false
	}
	removeConn()
	fqdn := s.Host + ".opengw.net"
	if _, err := ps(fmt.Sprintf(`Add-VpnConnection -Name '%s' -ServerAddress '%s' -TunnelType Sstp -EncryptionLevel Optional -AuthenticationMethod MSChapv2 -RememberCredential -Force -ErrorAction Stop`, connName, fqdn)); err == nil {
		if dial() == nil {
			return "SSTP", true
		}
	}
	removeConn()
	if cancelReq.Load() {
		return "", false
	}
	if _, err := ps(fmt.Sprintf(`Add-VpnConnection -Name '%s' -ServerAddress '%s' -TunnelType L2tp -L2tpPsk '%s' -EncryptionLevel Optional -AuthenticationMethod MSChapv2,Pap -RememberCredential -Force -ErrorAction Stop`, connName, s.IP, l2tpPSK)); err == nil {
		if dial() == nil {
			return "L2TP/IPsec", true
		}
	}
	removeConn()
	return "", false
}

func disconnectAll() {
	if mode == "wg" || engineRunning() {
		stopEngine()
	}
	if rasConnected() {
		removeConn()
	}
	mode = ""
}

// connectedOrAbort reports success unless the user pressed Cancel meanwhile.
func connectedOrAbort(label, cc string) {
	if cancelReq.Load() {
		disconnectAll()
		emit("disconnected", nil)
		return
	}
	emit("connected", map[string]string{"label": label, "cc": cc})
}

func connectServer(host string) {
	busy.Lock()
	defer busy.Unlock()
	cancelReq.Store(false)
	disconnectAll()
	srvMu.Lock()
	var s *Server
	for i := range servers {
		if servers[i].Host == host {
			s = &servers[i]
		}
	}
	srvMu.Unlock()
	if s == nil {
		emit("error", "Server not found — refresh the list.")
		return
	}
	emit("status", "Connecting to "+s.Country+"…")
	if proto, ok := tryVPNGate(*s); ok {
		mode = "ras"
		connectedOrAbort(s.Country+" · "+proto, s.CC)
		return
	}
	if cancelReq.Load() {
		return
	}
	emit("error", "This server refused. Pick another one (or press ⚡ Best).")
}

// connectUSAuto tries every free US, then Canada, VPN Gate server (Muse works in both).
func connectUSAuto() {
	busy.Lock()
	defer busy.Unlock()
	cancelReq.Store(false)
	disconnectAll()
	srvMu.Lock()
	var pool []Server
	for _, cc := range []string{"us", "ca"} {
		for _, s := range servers {
			if s.CC == cc {
				pool = append(pool, s)
			}
		}
	}
	srvMu.Unlock()
	if len(pool) == 0 {
		emit("error", "No free US/Canada server is online right now. Use a free Proton VPN config (button below) — it always has US servers.")
		return
	}
	if len(pool) > 5 {
		pool = pool[:5] // keep the wait short
	}
	for i, s := range pool {
		if cancelReq.Load() {
			return
		}
		emit("status", fmt.Sprintf("Trying %s server %d of %d…", s.Country, i+1, len(pool)))
		if proto, ok := tryVPNGate(s); ok {
			mode = "ras"
			connectedOrAbort(s.Country+" · "+proto, s.CC)
			return
		}
	}
	if cancelReq.Load() {
		return
	}
	emit("error", "Free US/Canada servers are busy. Import a free Proton VPN US config — it's the reliable option.")
}

func rasConnected() bool {
	out, _ := run("rasdial")
	return strings.Contains(out, connName)
}

// ---------------- WireGuard configs ----------------

var nameRe = regexp.MustCompile(`[^A-Za-z0-9 _\-#.]+`)

type ConfInfo struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func listConfs() []ConfInfo {
	var out []ConfInfo
	files, _ := filepath.Glob(filepath.Join(confDir(), "*.conf"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		ep := ""
		if c, err := ParseWGConf(string(b)); err == nil {
			ep = c.Endpoint
		}
		out = append(out, ConfInfo{Name: strings.TrimSuffix(filepath.Base(f), ".conf"), Endpoint: ep})
	}
	return out
}

func importConf(name, text string) (string, error) {
	if _, err := ParseWGConf(text); err != nil {
		return "", errors.New("Not a valid WireGuard config: " + err.Error())
	}
	name = strings.TrimSuffix(strings.TrimSpace(nameRe.ReplaceAllString(name, "")), ".conf")
	if name == "" {
		name = "USA"
	}
	return name, os.WriteFile(filepath.Join(confDir(), name+".conf"), []byte(text), 0o600)
}

func connectWG(name string) {
	busy.Lock()
	defer busy.Unlock()
	cancelReq.Store(false)
	disconnectAll()
	path := filepath.Join(confDir(), filepath.Base(name)+".conf")
	if _, err := os.Stat(path); err != nil {
		emit("error", "Config not found.")
		return
	}
	emit("status", "Starting WireGuard (click Yes on the Windows prompt)…")
	if err := startEngine(path); err != nil {
		emit("error", err.Error())
		return
	}
	mode = "wg"
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if cancelReq.Load() {
			stopEngine()
			mode = ""
			return
		}
		s := readStatus()
		switch {
		case s.State == "error":
			mode = ""
			emit("error", "WireGuard: "+s.Error)
			return
		case s.State == "up" && s.Handshake > 0:
			connectedOrAbort(name+" · WireGuard", "us")
			return
		case s.State == "up":
			emit("status", "Waiting for server handshake…")
		}
	}
	stopEngine()
	mode = ""
	emit("error", "Server did not answer. The config may be expired, or the free account is already connected on another device (Proton Free = 1 device at a time).")
}

// ---------------- IP / location ----------------

func ipInfo() (map[string]string, error) {
	resp, err := httpc.Get("http://ip-api.com/json/?fields=query,country,countryCode,city")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var info map[string]string
	err = json.NewDecoder(resp.Body).Decode(&info)
	return info, err
}

// ---------------- window size that fits small screens ----------------

func workArea() (int, int) {
	type rect struct{ L, T, R, B int32 }
	var r rect
	spi := syscall.NewLazyDLL("user32.dll").NewProc("SystemParametersInfoW")
	ret, _, _ := spi.Call(0x0030 /*SPI_GETWORKAREA*/, 0, uintptr(unsafe.Pointer(&r)), 0)
	if ret == 0 {
		return 1366, 728
	}
	return int(r.R - r.L), int(r.B - r.T)
}

// ---------------- main ----------------

func main() {
	// Elevated helper mode: runs only the WireGuard engine, no window.
	if len(os.Args) >= 3 && os.Args[1] == "--engine" {
		pid := 0
		if len(os.Args) >= 4 {
			pid, _ = strconv.Atoi(os.Args[3])
		}
		if len(os.Args) >= 5 {
			appDirOverride = os.Args[4]
		}
		runEngine(os.Args[2], pid)
		return
	}

	_, wh := workArea()
	height := 700
	if wh-40 < height {
		height = wh - 40
	}
	if height < 460 {
		height = 460
	}

	w = webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: "VPN Master " + version + " — The Master Sahib", Width: 440, Height: uint(height), IconId: 1, Center: true,
		},
	})
	if w == nil {
		run("mshta", `javascript:alert("VPN Master needs the Microsoft Edge WebView2 Runtime.\nFree download: go.microsoft.com/fwlink/p/?LinkId=2124703");close()`)
		return
	}
	defer w.Destroy()
	w.SetSize(380, 460, webview2.HintMin)
	w.SetSize(440, height, webview2.HintNone)

	w.Bind("vpnLoadServers", func() {
		go func() {
			list, src := fetchServers()
			srvMu.Lock()
			servers = list
			srvMu.Unlock()
			emit("servers", map[string]interface{}{"list": list, "source": src})
		}()
	})
	w.Bind("vpnConnect", func(host string) { go connectServer(host) })
	w.Bind("vpnConnectUS", func() { go connectUSAuto() })
	w.Bind("vpnConnectWG", func(name string) { go connectWG(name) })
	// Disconnect / Cancel works at any moment, even in the middle of connecting.
	w.Bind("vpnDisconnect", func() {
		cancelReq.Store(true)
		killCurrent()
		go func() {
			run("rasdial", connName, "/disconnect")
			stopEngine()
			removeConn()
			mode = ""
			emit("disconnected", nil)
		}()
	})
	w.Bind("vpnStatus", func() string {
		if engineRunning() {
			mode = "wg"
			return "wg"
		}
		if rasConnected() {
			mode = "ras"
			return "ras"
		}
		return ""
	})
	w.Bind("vpnStats", func() EngineStatus { return readStatus() })
	w.Bind("vpnIP", func() {
		go func() {
			if info, err := ipInfo(); err == nil {
				emit("ip", info)
			}
		}()
	})
	w.Bind("confList", func() []ConfInfo { return listConfs() })
	w.Bind("confImport", func(name, text string) (string, error) { return importConf(name, text) })
	w.Bind("confDelete", func(name string) { os.Remove(filepath.Join(confDir(), filepath.Base(name)+".conf")) })
	w.Bind("appVersion", func() string { return version })
	w.Bind("openURL", func(u string) {
		if strings.HasPrefix(u, "https://") {
			run("rundll32", "url.dll,FileProtocolHandler", u)
		}
	})

	w.SetHtml(indexHTML)
	w.Run()
	disconnectAll() // never leave a tunnel running after the window closes
}
