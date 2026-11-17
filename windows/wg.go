// WireGuard engine for VPN Master (Windows).
// Runs in a separate elevated copy of VPNMaster.exe ("engine mode"), because creating a
// network adapter (wintun) needs administrator rights. The UI talks to it through two
// small files: status.json (engine -> UI) and stop.flag (UI -> engine).
package main

import (
	"bufio"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

//go:embed wintun.dll
var wintunDLL []byte

// ---------------- config parsing (standard wg-quick .conf) ----------------

type WGConf struct {
	PrivateKey   string
	Addresses    []netip.Prefix
	DNS          []netip.Addr
	MTU          int
	PublicKey    string
	PresharedKey string
	AllowedIPs   []netip.Prefix
	Endpoint     string
	Keepalive    int
}

func keyHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != 32 {
		return "", errors.New("invalid key")
	}
	return hex.EncodeToString(b), nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func ParseWGConf(text string) (*WGConf, error) {
	c := &WGConf{MTU: 1280, Keepalive: 25}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])
		switch section + "." + k {
		case "interface.privatekey":
			c.PrivateKey = v
		case "interface.address":
			for _, s := range splitList(v) {
				if p, err := parsePrefix(s); err == nil {
					c.Addresses = append(c.Addresses, p)
				}
			}
		case "interface.dns":
			for _, s := range splitList(v) {
				if a, err := netip.ParseAddr(s); err == nil {
					c.DNS = append(c.DNS, a)
				}
			}
		case "interface.mtu":
			if n, err := strconv.Atoi(v); err == nil && n >= 576 {
				c.MTU = n
			}
		case "peer.publickey":
			c.PublicKey = v
		case "peer.presharedkey":
			c.PresharedKey = v
		case "peer.allowedips":
			for _, s := range splitList(v) {
				if p, err := parsePrefix(s); err == nil {
					c.AllowedIPs = append(c.AllowedIPs, p.Masked())
				}
			}
		case "peer.endpoint":
			c.Endpoint = v
		case "peer.persistentkeepalive":
			if n, err := strconv.Atoi(v); err == nil {
				c.Keepalive = n
			}
		}
	}
	if _, err := keyHex(c.PrivateKey); err != nil {
		return nil, errors.New("PrivateKey missing or invalid")
	}
	if _, err := keyHex(c.PublicKey); err != nil {
		return nil, errors.New("Peer PublicKey missing or invalid")
	}
	if len(c.Addresses) == 0 || c.Endpoint == "" {
		return nil, errors.New("Address or Endpoint missing")
	}
	if len(c.AllowedIPs) == 0 {
		c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	return c, nil
}

// ---------------- shared paths ----------------

var appDirOverride string

func appDir() string {
	d := filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNMaster")
	if appDirOverride != "" {
		d = appDirOverride
	}
	os.MkdirAll(d, 0o755)
	return d
}
func confDir() string { d := filepath.Join(appDir(), "configs"); os.MkdirAll(d, 0o755); return d }
func statusPath() string { return filepath.Join(appDir(), "status.json") }
func stopPath() string   { return filepath.Join(appDir(), "stop.flag") }

type EngineStatus struct {
	State     string `json:"state"` // starting | up | down | error
	Error     string `json:"error,omitempty"`
	Handshake int64  `json:"handshake"`
	Rx        int64  `json:"rx"`
	Tx        int64  `json:"tx"`
	PID       int    `json:"pid"`
	Time      int64  `json:"time"`
}

func writeStatus(s EngineStatus) {
	s.PID = os.Getpid()
	s.Time = time.Now().Unix()
	b, _ := json.Marshal(s)
	tmp := statusPath() + ".tmp"
	os.WriteFile(tmp, b, 0o644)
	os.Rename(tmp, statusPath())
}

func readStatus() EngineStatus {
	var s EngineStatus
	b, err := os.ReadFile(statusPath())
	if err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	ev, _ := windows.WaitForSingleObject(h, 0)
	return ev == uint32(windows.WAIT_TIMEOUT)
}

// ---------------- engine (elevated process) ----------------

func defaultRoute4(exclude winipcfg.LUID) (winipcfg.LUID, netip.Addr, bool) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, netip.Addr{}, false
	}
	best := uint32(1<<32 - 1)
	var luid winipcfg.LUID
	var gw netip.Addr
	ok := false
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == exclude {
			continue
		}
		metric := r.Metric
		if ifc, err := r.InterfaceLUID.IPInterface(windows.AF_INET); err == nil {
			if !ifc.Connected {
				continue
			}
			metric += ifc.Metric
		}
		if metric < best {
			best, luid, gw, ok = metric, r.InterfaceLUID, r.NextHop.Addr(), true
		}
	}
	return luid, gw, ok
}

func splitDefault(p netip.Prefix) []netip.Prefix {
	if p.Bits() != 0 {
		return []netip.Prefix{p}
	}
	if p.Addr().Is4() {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	}
	return []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
}

func runEngine(confFile string, parentPID int) {
	os.Remove(stopPath())
	fail := func(err error) {
		writeStatus(EngineStatus{State: "error", Error: err.Error()})
	}
	writeStatus(EngineStatus{State: "starting"})

	raw, err := os.ReadFile(confFile)
	if err != nil {
		fail(err)
		return
	}
	c, err := ParseWGConf(string(raw))
	if err != nil {
		fail(err)
		return
	}

	// Resolve endpoint (prefer IPv4).
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		fail(fmt.Errorf("bad Endpoint: %v", err))
		return
	}
	var epIP netip.Addr
	if a, e := netip.ParseAddr(host); e == nil {
		epIP = a
	} else {
		ips, e := net.LookupIP(host)
		if e != nil || len(ips) == 0 {
			if a, e2 := dohResolve(host); e2 == nil {
				epIP = a
			} else {
				fail(fmt.Errorf("cannot resolve %s", host))
				return
			}
		} else {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					epIP, _ = netip.AddrFromSlice(ip4)
					break
				}
			}
			if !epIP.IsValid() {
				epIP, _ = netip.AddrFromSlice(ips[0])
			}
		}
	}

	// Remember the real internet route so the encrypted packets don't loop into the tunnel.
	defLUID, defGW, haveDef := defaultRoute4(0)

	tdev, err := tun.CreateTUN("VPN Master", c.MTU)
	if err != nil {
		fail(fmt.Errorf("could not create network adapter: %v", err))
		return
	}
	nt := tdev.(*tun.NativeTun)
	luid := winipcfg.LUID(nt.LUID())

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	priv, _ := keyHex(c.PrivateKey)
	pub, _ := keyHex(c.PublicKey)
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\nreplace_peers=true\npublic_key=%s\n", priv, pub)
	if psk, e := keyHex(c.PresharedKey); e == nil {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&uapi, "endpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n",
		net.JoinHostPort(epIP.String(), port), c.Keepalive)
	for _, p := range c.AllowedIPs {
		fmt.Fprintf(&uapi, "allowed_ip=%s\n", p.String())
	}
	cleanup := func() {
		if haveDef && epIP.Is4() {
			defLUID.DeleteRoute(netip.PrefixFrom(epIP, 32), defGW)
		}
		dev.Close()
	}
	if err = dev.IpcSet(uapi.String()); err != nil {
		cleanup()
		fail(err)
		return
	}
	if err = dev.Up(); err != nil {
		cleanup()
		fail(err)
		return
	}

	// Interface addressing, metric, DNS, routes.
	if err = luid.SetIPAddresses(c.Addresses); err != nil {
		cleanup()
		fail(fmt.Errorf("set address: %v", err))
		return
	}
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if ifc, e := luid.IPInterface(fam); e == nil {
			ifc.UseAutomaticMetric = false
			ifc.Metric = 0
			if fam == windows.AF_INET {
				ifc.NLMTU = uint32(c.MTU)
			}
			ifc.Set()
		}
	}
	if haveDef && epIP.Is4() {
		defLUID.AddRoute(netip.PrefixFrom(epIP, 32), defGW, 0)
	}
	for _, p := range c.AllowedIPs {
		for _, sp := range splitDefault(p) {
			nh := netip.IPv4Unspecified()
			if sp.Addr().Is6() {
				nh = netip.IPv6Unspecified()
			}
			luid.AddRoute(sp, nh, 0) // IPv6 may fail without a v6 address — harmless
		}
	}
	var dns4, dns6 []netip.Addr
	for _, d := range c.DNS {
		if d.Is4() {
			dns4 = append(dns4, d)
		} else {
			dns6 = append(dns6, d)
		}
	}
	if len(dns4) == 0 {
		dns4 = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	luid.SetDNS(windows.AF_INET, dns4, nil)
	if len(dns6) > 0 {
		luid.SetDNS(windows.AF_INET6, dns6, nil)
	}

	// Main loop: report stats, obey stop flag, die with the UI.
	for {
		st := EngineStatus{State: "up"}
		if s, e := dev.IpcGet(); e == nil {
			for _, l := range strings.Split(s, "\n") {
				kv := strings.SplitN(l, "=", 2)
				if len(kv) != 2 {
					continue
				}
				n, _ := strconv.ParseInt(kv[1], 10, 64)
				switch kv[0] {
				case "last_handshake_time_sec":
					st.Handshake = n
				case "rx_bytes":
					st.Rx += n
				case "tx_bytes":
					st.Tx += n
				}
			}
		}
		writeStatus(st)
		if _, e := os.Stat(stopPath()); e == nil {
			break
		}
		if parentPID > 0 && !processAlive(parentPID) {
			break
		}
		time.Sleep(time.Second)
	}
	cleanup()
	os.Remove(stopPath())
	writeStatus(EngineStatus{State: "down"})
}

// ---------------- UI side: start/stop the elevated engine ----------------

func installEngine() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(appDir(), "engine")
	os.MkdirAll(dir, 0o755)
	dst := filepath.Join(dir, "VPNMaster-engine.exe")
	src, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	if old, e := os.ReadFile(dst); e != nil || len(old) != len(src) {
		if err = os.WriteFile(dst, src, 0o755); err != nil {
			return "", err
		}
	}
	dll := filepath.Join(dir, "wintun.dll")
	if fi, e := os.Stat(dll); e != nil || fi.Size() != int64(len(wintunDLL)) {
		if err = os.WriteFile(dll, wintunDLL, 0o644); err != nil {
			return "", err
		}
	}
	return dst, nil
}

func startEngine(confFile string) error {
	exe, err := installEngine()
	if err != nil {
		return err
	}
	os.Remove(stopPath())
	os.Remove(statusPath())
	args := fmt.Sprintf(`--engine "%s" %d "%s"`, confFile, os.Getpid(), appDir())
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err = windows.ShellExecute(0, verb, file, params, dir, windows.SW_HIDE); err != nil {
		return errors.New("Administrator permission is needed for USA mode (click Yes on the Windows prompt)")
	}
	return nil
}

func stopEngine() {
	s := readStatus()
	if s.State != "up" && s.State != "starting" {
		return
	}
	os.WriteFile(stopPath(), []byte("1"), 0o644)
	for i := 0; i < 40; i++ {
		time.Sleep(200 * time.Millisecond)
		if st := readStatus(); st.State == "down" || st.State == "error" || (st.PID > 0 && !processAlive(st.PID)) {
			return
		}
	}
}

func engineRunning() bool {
	s := readStatus()
	return s.State == "up" && s.PID > 0 && processAlive(s.PID)
}
