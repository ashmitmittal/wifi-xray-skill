#!/usr/bin/env python3
import argparse
import concurrent.futures
import datetime
import html
import http.client
import ipaddress
import json
import math
import os
import platform
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

VERSION = "0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
TEMPLATE = os.path.join(SKILL, "assets", "template.html")
EXAMPLE = os.path.join(SKILL, "examples", "sample-home")
CACHE = os.path.join(os.path.expanduser("~"), ".cache", "wifi-xray")
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
SPEED_HOST = "speed.cloudflare.com"
OS = "mac" if sys.platform == "darwin" else "win" if sys.platform.startswith("win") else "other"
SELF = {"mac": "This Mac", "win": "This PC"}
BAND = {"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}
LEVELS = ["none", "low", "medium", "high"]
POINTS = {"strong": 3, "audible": 1, "faint": 0}


def say(*a):
    print(*a, flush=True)


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


class Raw:
    def __init__(self, folder, replay=False):
        self.dir = os.path.join(folder, "raw")
        self.replay = replay
        os.makedirs(self.dir, exist_ok=True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def has(self, name):
        return os.path.exists(self.path(name))

    def read(self, name):
        if not self.has(name):
            return ""
        with open(self.path(name), encoding="utf-8", errors="replace") as f:
            return f.read()

    def write(self, name, text):
        with open(self.path(name), "w", encoding="utf-8") as f:
            f.write(text)

    def get(self, name, cmd, timeout=30):
        if self.replay:
            return self.read(name)
        out = run(cmd, timeout)
        self.write(name, out)
        return out


def norm_mac(m):
    parts = re.split(r"[:\-]", (m or "").strip())
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p, 16):02X}" for p in parts)
    except ValueError:
        return None


def is_private_mac(mac):
    return bool(mac) and int(mac[:2], 16) & 2 == 2


def host_mac(raw):
    out = raw.get("route.txt", ["route", "-n", "get", "default"])
    gw = re.search(r"gateway:\s*(\S+)", out)
    itf = re.search(r"interface:\s*(\S+)", out)
    iface = itf.group(1) if itf else "en0"
    ip = raw.get("ip.txt", ["ipconfig", "getifaddr", iface]).strip()
    mask = raw.get("mask.txt", ["ipconfig", "getoption", iface, "subnet_mask"]).strip()
    return {"ip": ip or None, "mask": mask or None, "gateway": gw.group(1) if gw else None, "iface": iface}


def host_win(raw):
    out = raw.get("ipconfig.txt", ["ipconfig"])
    v4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
    for block in re.split(r"\r?\n(?=\S)", out):
        ip = re.search(r"IPv4[^:\n]*:\s*" + v4, block)
        gw = re.search(r"Default Gateway[^:\n]*:(?:[^\n]*\n\s+)?[^\d\n]*" + v4, block)
        gw = gw or re.search(r"Default Gateway[^:\n]*:\s*" + v4, block)
        mask = re.search(r"Subnet Mask[^:\n]*:\s*" + v4, block)
        if ip and gw:
            return {"ip": ip.group(1), "mask": mask.group(1) if mask else "255.255.255.0", "gateway": gw.group(1), "iface": None}
    return None


def host_guess():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
    except OSError:
        ip = None
    finally:
        s.close()
    if not ip:
        return {"ip": None, "mask": None, "gateway": None, "iface": None}
    return {"ip": ip, "mask": "255.255.255.0", "gateway": ".".join(ip.split(".")[:3] + ["1"]), "iface": None, "guessed": True}


SEC_MAC = [("wpa3_transition", "WPA2/WPA3"), ("wpa3", "WPA3"), ("wpa2_personal_mixed", "WPA/WPA2"), ("wpa2_enterprise", "WPA2-Enterprise"),
           ("wpa2", "WPA2-Personal"), ("wpa_enterprise", "WPA-Enterprise"), ("wpa", "WPA"), ("wep", "WEP"), ("owe", "Open, encrypted"), ("none", "Open")]


def sec_mac(s):
    s = (s or "").replace("spairport_security_mode_", "").lower()
    for k, v in SEC_MAC:
        if k in s:
            return v
    return s or None


def chan_mac(s):
    s = str(s or "")
    ch = re.match(r"\s*(\d+)", s)
    if not ch:
        return None
    ch = int(ch.group(1))
    b = re.search(r"(\d)\s*GHz", s)
    w = re.search(r"(\d+)\s*MHz", s)
    band = {"2": "2g", "5": "5g", "6": "6g"}.get(b.group(1)) if b else ("2g" if ch <= 14 else "5g")
    width = int(w.group(1)) if w else (40 if re.search(r",\s*[+-]1", s) else 20)
    return ch, band, width


def sig_noise(s):
    v = [int(x) for x in re.findall(r"-\d+", str(s or ""))]
    return (v[0] if v else None), (v[1] if len(v) > 1 else None)


VHT1 = {20: [7.2, 14.4, 21.7, 28.9, 43.3, 57.8, 65, 72.2, 86.7, 96.3], 40: [15, 30, 45, 60, 90, 120, 135, 150, 180, 200],
        80: [32.5, 65, 97.5, 130, 195, 260, 292.5, 325, 390, 433.3], 160: [65, 130, 195, 260, 390, 520, 585, 650, 780, 866.7]}


def streams(phy, width, mcs, rate):
    if not rate or mcs is None or "ax" in (phy or "") or "be" in (phy or ""):
        return None
    row = VHT1.get(width)
    if not row or not 0 <= mcs < len(row):
        return None
    n = rate / row[mcs]
    return round(n) if 1 <= round(n) <= 4 and abs(n - round(n)) < .12 else None


def wifi_mac(raw):
    notes = []
    try:
        data = json.loads(raw.get("airport.json", ["system_profiler", "SPAirPortDataType", "-json"], 90))
    except ValueError:
        return None, [], ["Could not read Wi-Fi details from system_profiler."]
    for item in data.get("SPAirPortDataType", []):
        for itf in item.get("spairport_airport_interfaces", []):
            cur = itf.get("spairport_current_network_information")
            c = chan_mac(cur.get("spairport_network_channel")) if cur else None
            if not c:
                continue
            sig, noise = sig_noise(cur.get("spairport_signal_noise"))
            name = cur.get("_name")
            hidden = not name or "redacted" in name
            phy = cur.get("spairport_network_phymode")
            rate, mcs = cur.get("spairport_network_rate"), cur.get("spairport_network_mcs")
            link = {"ssid": None if hidden else name, "band": c[1], "channel": c[0], "width": c[2], "signal": sig, "noise": noise, "rate": rate,
                    "mcs": mcs, "phy": phy, "streams": streams(phy, c[2], mcs, rate), "security": sec_mac(cur.get("spairport_security_mode"))}
            nets = []
            for o in itf.get("spairport_airport_other_local_wireless_networks", []):
                oc = chan_mac(o.get("spairport_network_channel"))
                os_, _ = sig_noise(o.get("spairport_signal_noise"))
                if not oc or os_ is None:
                    continue
                on = o.get("_name")
                oh = not on or "redacted" in on
                hidden = hidden or oh
                nets.append({"ssid": None if oh else on, "band": oc[1], "channel": oc[0], "width": oc[2], "signal": os_,
                             "phy": o.get("spairport_network_phymode"), "security": sec_mac(o.get("spairport_security_mode"))})
            if hidden:
                notes.append("macOS hides Wi-Fi network names from command-line tools, so nearby networks are shown by channel and strength only.")
            return link, nets, notes
    return None, [], ["This computer is not connected to Wi-Fi."]


def pct_dbm(p):
    return round(p / 2 - 100)


def band_of(text, ch):
    m = re.search(r"(2\.4|5|6)\s*GHz", text or "")
    if m:
        return {"2.4": "2g", "5": "5g", "6": "6g"}[m.group(1)]
    return "2g" if ch <= 14 else "5g"


def width_guess(band, phy):
    if band == "2g":
        return 20
    return 80 if re.search(r"ac|ax|be", phy or "") else 40


def wifi_win(raw):
    notes = []
    itf = raw.get("netsh-interfaces.txt", ["netsh", "wlan", "show", "interfaces"])
    lst = raw.get("netsh-networks.txt", ["netsh", "wlan", "show", "networks", "mode=bssid"])
    f = {}
    for line in itf.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            f.setdefault(k.strip().lower(), v.strip())
    if re.search(r"location", itf + lst, re.I) and not re.search(r"BSSID", lst):
        notes.append("Windows blocked the Wi-Fi scan. Turn on Location services (Settings > Privacy & security > Location), allow desktop apps, and run the scan again.")
    link = None
    num = lambda s: int(re.search(r"-?\d+", s).group()) if s and re.search(r"-?\d+", s) else None
    if f.get("channel") and (f.get("signal") or f.get("rssi")):
        ch = num(f["channel"])
        phy = f.get("radio type")
        band = band_of(f.get("band"), ch)
        sig = num(f.get("rssi")) if f.get("rssi") else pct_dbm(num(f["signal"]))
        tx = f.get("transmit rate (mbps)") or f.get("receive rate (mbps)")
        link = {"ssid": f.get("ssid") or None, "bssid": norm_mac(f.get("ap bssid") or f.get("bssid") or ""), "band": band, "channel": ch,
                "width": width_guess(band, phy), "widthGuessed": True, "signal": sig, "noise": None, "rate": round(float(tx)) if tx else None,
                "mcs": None, "phy": phy, "streams": None, "security": f.get("authentication")}
        notes.append("Windows does not report channel width, so widths are assumed from the Wi-Fi standard.")
    nets, ssid, auth, cur = [], None, None, None
    for line in lst.splitlines():
        m = re.match(r"\s*SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            ssid, auth, cur = m.group(1).strip() or None, None, None
            continue
        m = re.match(r"\s*BSSID\s+\d+\s*:\s*(\S+)", line)
        if m:
            cur = {"ssid": ssid, "bssid": norm_mac(m.group(1)), "security": auth, "band": None, "channel": None, "signal": None, "phy": None}
            nets.append(cur)
            continue
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        k = k.lower()
        if k == "authentication" and cur is None:
            auth = v
        elif cur is not None and k == "signal" and num(v) is not None:
            cur["signal"] = pct_dbm(num(v))
        elif cur is not None and k == "radio type":
            cur["phy"] = v
        elif cur is not None and k == "band":
            cur["bandText"] = v
        elif cur is not None and k == "channel" and num(v) is not None:
            cur["channel"] = num(v)
        elif cur is not None and k == "channel utilization":
            p = re.search(r"\((\d+)\s*%\)", v)
            cur["busy"] = int(p.group(1)) if p else None
    out = []
    for n in nets:
        if n["channel"] is None or n["signal"] is None:
            continue
        n["band"] = band_of(n.pop("bandText", None), n["channel"])
        n["width"] = width_guess(n["band"], n["phy"])
        out.append(n)
    return link, out, notes


def speed_nq(raw):
    try:
        d = json.loads(raw.get("speed.json", ["networkQuality", "-c"], 120))
    except ValueError:
        return None
    down, up, rpm, base = d.get("dl_throughput"), d.get("ul_throughput"), d.get("responsiveness"), d.get("base_rtt")
    if not down:
        return None
    return {"down": round(down / 1e6, 1), "up": round((up or 0) / 1e6, 1), "idle": round(base) if base else None,
            "loaded": round(60000 / rpm) if rpm else None, "rpm": round(rpm) if rpm else None, "method": "networkQuality"}


def tcp_ms(host, port=443, timeout=3):
    t = time.perf_counter()
    try:
        socket.create_connection((host, port), timeout).close()
        return (time.perf_counter() - t) * 1000
    except OSError:
        return None


def speed_http(seconds=7):
    idle = [v for v in (tcp_ms(SPEED_HOST) for _ in range(5)) if v]
    if not idle:
        return None
    lock = threading.Lock()

    def phase(worker, n):
        stop, count, lat = threading.Event(), [0], []

        def probe():
            while not stop.is_set():
                v = tcp_ms(SPEED_HOST)
                if v:
                    lat.append(v)
                time.sleep(.3)

        ts = [threading.Thread(target=worker, args=(stop, count), daemon=True) for _ in range(n)] + [threading.Thread(target=probe, daemon=True)]
        for t in ts:
            t.start()
        time.sleep(1.2)
        with lock:
            b0 = count[0]
        t0 = time.perf_counter()
        time.sleep(seconds)
        with lock:
            b1 = count[0]
        dt = time.perf_counter() - t0
        stop.set()
        return (b1 - b0) * 8 / dt / 1e6, lat

    def down(stop, count):
        try:
            c = http.client.HTTPSConnection(SPEED_HOST, timeout=10)
            while not stop.is_set():
                c.request("GET", "/__down?bytes=25000000", headers={"User-Agent": "wifi-xray"})
                r = c.getresponse()
                if r.status != 200:
                    break
                while not stop.is_set():
                    b = r.read(65536)
                    if not b:
                        break
                    with lock:
                        count[0] += len(b)
            c.close()
        except (OSError, http.client.HTTPException):
            pass

    def up(stop, count):
        chunk, size = b"0" * 65536, 64 * 65536
        try:
            c = http.client.HTTPSConnection(SPEED_HOST, timeout=10)
            while not stop.is_set():
                c.putrequest("POST", "/__up")
                c.putheader("Content-Length", str(size))
                c.putheader("Content-Type", "application/octet-stream")
                c.putheader("User-Agent", "wifi-xray")
                c.endheaders()
                for _ in range(size // len(chunk)):
                    c.send(chunk)
                    with lock:
                        count[0] += len(chunk)
                r = c.getresponse()
                r.read()
                if r.status != 200:
                    break
            c.close()
        except (OSError, http.client.HTTPException):
            pass

    d, lat = phase(down, 4)
    u, _ = phase(up, 3)
    if d <= 0:
        return None
    return {"down": round(d, 1), "up": round(u, 1), "idle": round(statistics.median(idle)), "loaded": round(statistics.median(lat)) if lat else None,
            "rpm": None, "method": "http"}


def parse_arp(txt):
    out = {}
    for line in txt.splitlines():
        m = re.search(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9A-Fa-f]{1,2}(?:[:\-][0-9A-Fa-f]{1,2}){5})\b", line)
        if not m:
            continue
        ip, mac = m.group(1), norm_mac(m.group(2))
        first, last = int(ip.split(".")[0]), int(ip.split(".")[3])
        if not mac or mac == "FF:FF:FF:FF:FF:FF" or mac.startswith("01:00:5E") or mac.startswith("33:33") or first >= 224 or last == 255:
            continue
        out[ip] = mac
    return out


def sweep(hosts):
    if OS == "win":
        cmd = lambda ip: ["ping", "-n", "1", "-w", "700", ip]
    else:
        cmd = lambda ip: ["ping", "-c", "1", "-W", "700" if OS == "mac" else "1", ip]

    def one(ip):
        try:
            subprocess.run(cmd(ip), capture_output=True, timeout=4)
        except (OSError, subprocess.SubprocessError):
            pass

    for _ in range(2):
        with concurrent.futures.ThreadPoolExecutor(64) as ex:
            list(ex.map(one, hosts))
        time.sleep(1)


def lookup_names(ips):
    out = {}

    def one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except OSError:
            return ip, None

    ex = concurrent.futures.ThreadPoolExecutor(32)
    futs = [ex.submit(one, ip) for ip in ips]
    done, _ = concurrent.futures.wait(futs, timeout=6)
    for f in done:
        ip, n = f.result()
        if n and not re.match(r"^[\d.]+$", n):
            out[ip] = re.sub(r"\.(local|lan|home|localdomain|home\.arpa)\.?$", "", n, flags=re.I)
    ex.shutdown(wait=False, cancel_futures=True)
    return out


_manuf = None


def manuf(download=True):
    global _manuf
    if _manuf is not None:
        return _manuf
    path = os.path.join(CACHE, "manuf")
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < 90 * 86400
    if not fresh and download:
        try:
            os.makedirs(CACHE, exist_ok=True)
            req = urllib.request.Request(MANUF_URL, headers={"User-Agent": "wifi-xray"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = r.read()
            if len(data) > 200000:
                with open(path, "wb") as f:
                    f.write(data)
        except (OSError, ValueError):
            pass
    _manuf = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                p = [x.strip() for x in line.split("\t")]
                if len(p) >= 2 and re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2}$", p[0]):
                    _manuf[p[0].upper()] = p[2] if len(p) > 2 and p[2] else p[1]
    return _manuf


SUFFIX = re.compile(r"[,.]?\s+(inc|ltd|llc|co|corp|corporation|limited|company|gmbh|s\.?a\.?|ag|bv|pte|pvt|technologies|technology|electronics|communications?|international|holdings?|group|mobile|systems?|telecommunications?|\(shenzhen\)|\(china\))\.?$", re.I)


def vendor_of(mac, download=True):
    if not mac or is_private_mac(mac):
        return None
    v = manuf(download).get(mac[:8])
    if not v or "IEEE Registration" in v:
        return None
    for _ in range(4):
        v = SUFFIX.sub("", v).strip(" ,.")
    return v or None


BRANDS = [(r"tp-?link|tpencrypt|archer|deco", "TP-Link"), (r"d-?link", "D-Link"), (r"tenda", "Tenda"), (r"netgear", "Netgear"), (r"jio", "Jio"),
          (r"airtel", "Airtel"), (r"huawei", "Huawei"), (r"\bzte\b", "ZTE"), (r"nokia", "Nokia"), (r"syrotech", "Syrotech"), (r"genexis", "Genexis"),
          (r"mercusys", "Mercusys"), (r"asus", "ASUS"), (r"xiaomi|miwifi", "Xiaomi"), (r"linksys", "Linksys"), (r"openwrt|luci", "OpenWrt"),
          (r"mikrotik|routeros", "MikroTik"), (r"ubiquiti|unifi", "Ubiquiti"), (r"fritz", "FRITZ!Box"), (r"sercomm", "Sercomm")]


def brand_in(text):
    for pat, name in BRANDS:
        if re.search(pat, text or "", re.I):
            return name
    return None


def gateway_page(raw, ip):
    if raw.replay:
        body = raw.read("gateway.html")
    else:
        body = ""
        try:
            req = urllib.request.Request(f"http://{ip}/", headers={"User-Agent": "Mozilla/5.0 (wifi-xray)"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read(300000).decode("utf-8", "replace")
        except (OSError, ValueError):
            body = ""
        raw.write("gateway.html", body)
    if not body:
        return {}
    title = re.search(r"<title[^>]*>([^<]{1,80})", body, re.I)
    model = re.search(r"\b(Archer\s+[A-Z]{1,3}\d{1,4}\w*|TL-[A-Z0-9]{4,}|DIR-\d{3,4}\w*|RT-[A-Z]{1,3}\d{2,4}\w*)\b", body)
    return {"title": title.group(1).strip() if title else None, "brand": brand_in(body), "model": model.group(1) if model else None}


def cmd_scan(a):
    os.makedirs(a.out, exist_ok=True)
    raw = Raw(a.out, a.replay)
    kind = ("mac" if raw.has("airport.json") else "win" if raw.has("netsh-interfaces.txt") else OS) if a.replay else OS
    if kind == "other":
        sys.exit("This scanner supports macOS and Windows. On other systems, collect the readings yourself and write scan.json as described in references/data-format.md.")
    meta = {}
    if a.replay and raw.has("meta.json"):
        meta = json.loads(raw.read("meta.json"))
    else:
        meta = {"time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                "platform": f"{'macOS' if kind == 'mac' else 'Windows'} {platform.mac_ver()[0] if kind == 'mac' else platform.release()}".strip()}
        raw.write("meta.json", json.dumps(meta))
    notes = []

    say("Reading this computer's address and the router's address...")
    host = (host_mac(raw) if kind == "mac" else host_win(raw)) or host_guess()
    if host.get("guessed"):
        notes.append("Could not read the router's address; assumed it ends in .1.")

    say("Reading the Wi-Fi link and nearby networks...")
    link, nets, n2 = wifi_mac(raw) if kind == "mac" else wifi_win(raw)
    notes += n2
    if not link:
        say("  " + (n2[0] if n2 else "No Wi-Fi link found."))

    net = None
    if host.get("ip") and host.get("mask"):
        try:
            net = ipaddress.ip_network(f"{host['ip']}/{host['mask']}", strict=False)
        except ValueError:
            net = None
    devices, gateway = [], {"ip": host.get("gateway")}
    look = not a.no_devices and net is not None
    if look and not net.is_private:
        look = False
        notes.append("This computer has a public address, so the device search was skipped.")
    if look and net.num_addresses > 256:
        if a.big_network:
            net = ipaddress.ip_network(f"{host['ip']}/24", strict=False)
        else:
            look = False
            notes.append(f"This network has room for {net.num_addresses - 2} devices, which is larger than a home network, so the device search was skipped. "
                         "If it is your own network, run the scan again with --big-network.")
    if a.no_devices:
        notes.append("Device search was switched off for this scan.")
    if look:
        if not a.replay:
            say(f"Looking for devices on {net} (one ping to each address, twice)...")
            sweep([str(h) for h in net.hosts()])
        arp = parse_arp(raw.get("arp.txt", ["arp", "-a"] if kind == "win" else ["arp", "-an"]))
        arp = {ip: mac for ip, mac in arp.items() if ipaddress.ip_address(ip) in net}
        if raw.replay:
            names = json.loads(raw.read("names.json") or "{}")
        else:
            names = lookup_names([ip for ip in arp if ip != host.get("gateway")])
            raw.write("names.json", json.dumps(names))
        for ip in sorted(arp, key=lambda x: tuple(int(p) for p in x.split("."))):
            mac = arp[ip]
            if ip == host.get("gateway"):
                gateway["mac"] = mac
                gateway["vendor"] = vendor_of(mac, not a.replay)
                continue
            devices.append({"ip": ip, "mac": mac, "name": names.get(ip), "vendor": vendor_of(mac, not a.replay), "private": is_private_mac(mac), "me": ip == host.get("ip")})
        if host.get("ip") and not any(d["me"] for d in devices):
            devices.append({"ip": host["ip"], "mac": None, "name": None, "vendor": None, "private": False, "me": True})
        if not arp and kind == "mac":
            notes.append("macOS did not let this copy of Python see the other devices on the network, so the device list is empty. "
                         "Run the scan with /usr/bin/python3 instead, or allow Python under System Settings > Privacy & Security > Local Network.")
        else:
            notes.append("Devices were found by pinging each address. Phones that are asleep often do not answer, so the list can be short.")
    if host.get("gateway"):
        gateway.update({k: v for k, v in gateway_page(raw, host["gateway"]).items() if v})
        gateway.setdefault("brand", brand_in(gateway.get("vendor") or ""))

    speed = None
    if a.no_speed:
        notes.append("Speed test was switched off for this scan.")
    elif a.replay:
        speed = speed_nq(raw) if raw.has("speed.json") else json.loads(raw.read("speed-http.json") or "null")
    else:
        say("Running the speed and lag test (about 20 seconds, uses some data)...")
        speed = speed_nq(raw) if kind == "mac" else None
        if not speed:
            speed = speed_http()
            raw.write("speed-http.json", json.dumps(speed))
        if not speed:
            notes.append("The speed test did not finish.")

    scan = {"version": 1, "scannedAt": meta["time"], "platform": meta["platform"], "self": SELF.get(kind, "This computer"), "host": host,
            "gateway": gateway, "link": link, "networks": nets, "speed": speed, "devices": devices, "notes": notes}
    with open(os.path.join(a.out, "scan.json"), "w", encoding="utf-8") as f:
        json.dump(scan, f, indent=1, ensure_ascii=False)

    say("")
    if link:
        say(f"Link      {BAND.get(link['band'], link['band'])} channel {link['channel']}, {link['width']} MHz, signal {link['signal']} dBm"
            + (f", noise {link['noise']} dBm" if link.get("noise") is not None else "") + (f", {link['rate']} Mbps" if link.get("rate") else ""))
    say(f"Nearby    {len(nets)} networks" + ("" if any(n.get('ssid') for n in nets) or not nets else " (names hidden)"))
    if speed:
        say(f"Speed     {speed['down']} Mbps down, {speed['up']} Mbps up" + (f", ping {speed['idle']} ms idle and {speed['loaded']} ms under load" if speed.get("loaded") else ""))
    say(f"Devices   {len(devices)} answered" if look else "Devices   not searched")
    say(f"Router    {gateway.get('ip') or 'not found'}" + (f" ({gateway.get('model') or gateway.get('brand') or gateway.get('vendor')})" if gateway.get("model") or gateway.get("brand") or gateway.get("vendor") else ""))
    for n in notes:
        say("Note      " + n)
    say(f"\nSaved {os.path.join(a.out, 'scan.json')}")
    if gateway.get("ip"):
        say(f"Router login page: http://{gateway['ip']}/")


def chf(band, c):
    return 2407 + 5 * c if band == "2g" else 5000 + 5 * c


def center(band, ch, w):
    if band == "2g":
        return (ch + 2 if ch <= 7 else ch - 2) if w >= 40 else ch
    if w <= 20:
        return ch
    base = 149 if ch >= 149 else 100 if ch >= 100 else 36
    step = 32 if w >= 160 else 16 if w >= 80 else 8
    return base + ((ch - base) // step) * step + (14 if w >= 160 else 6 if w >= 80 else 2)


def span(band, ch, w):
    f = chf(band, center(band, ch, w))
    half = (22 if band == "2g" and w <= 20 else w) / 2
    return f - half, f + half


def overlaps(band, c1, w1, c2, w2):
    a, b = span(band, c1, w1), span(band, c2, w2)
    return a[0] < b[1] and b[0] < a[1]


def level_of(sig):
    return "strong" if sig >= -70 else "audible" if sig >= -82 else "faint"


def standard(phy, band, mode=None):
    p = (mode or phy or "").lower()
    p = re.sub(r"802\.11", "", p)
    if "be" in p:
        return "Wi-Fi 7 · 802.11be"
    if "ax" in p:
        return "Wi-Fi 6 · 802.11ax"
    if "ac" in p and (band != "2g" or mode):
        return "Wi-Fi 5 · 802.11ac"
    if "n" in p:
        return "Wi-Fi 4 · 802.11n"
    return (mode or phy or "").strip() or None


def band_id(v):
    s = str(v or "").lower().replace(" ", "")
    if s in ("wired", "lan", "ethernet", "cable"):
        return "wired"
    if s.startswith("2") or "2.4" in s:
        return "2g"
    if s.startswith("5"):
        return "5g"
    if s.startswith("6"):
        return "6g"
    return None


NAME_BRAND = [(r"iphone|ipad|macbook|imac|\bmac\b|apple|airpods|homepod|watch", "Apple"), (r"galaxy|samsung", "Samsung"), (r"oneplus", "OnePlus"),
              (r"pixel|nest|chromecast|google", "Google"), (r"redmi|xiaomi|poco|\bmi[- ]", "Xiaomi"), (r"realme", "realme"), (r"oppo", "OPPO"),
              (r"vivo", "vivo"), (r"echo|alexa|fire-?tv|kindle|amazon", "Amazon"), (r"\bhp\b|deskjet|laserjet|ink ?tank", "HP"), (r"\bdell\b", "Dell"),
              (r"lenovo|thinkpad", "Lenovo"), (r"playstation|\bps[45]\b|bravia|sony", "Sony"), (r"xbox|surface", "Microsoft"), (r"\blg\b|webos", "LG")]
KINDS = [("tablet", r"ipad|\btab\b|tablet|galaxy-?tab"), ("phone", r"iphone|android|pixel|oneplus|galaxy|redmi|poco|realme|oppo|vivo|nokia|moto|phone|\bnord\b"),
         ("tv", r"\btv\b|bravia|fire-?tv|firestick|chromecast|roku|webos|android-?tv|shield"), ("speaker", r"echo|alexa|homepod|nest-?(mini|audio|hub)|sonos|speaker"),
         ("printer", r"printer|deskjet|laserjet|ink ?tank|epson|canon|brother|\bhp[0-9a-f]{4,}"), ("console", r"playstation|\bps[45]\b|xbox|switch|steam-?deck"),
         ("camera", r"\bcam\b|camera|doorbell|\bring\b|tapo|ezviz|hikvision"), ("bulb", r"bulb|plug|light|lamp|tuya|espressif|shelly|wipro|wiz|smart-?life|tasmota|esp[-_]?[0-9a-f]{3,}"),
         ("laptop", r"macbook|imac|\bmac\b|laptop|desktop|thinkpad|\bpc\b|windows|surface|dell|lenovo|workstation")]


def kind_of(text):
    for k, pat in KINDS:
        if re.search(pat, text or "", re.I):
            return k
    return "unknown"


def brand_from_name(name):
    for pat, b in NAME_BRAND:
        if re.search(pat, name or "", re.I):
            return b
    return None


def own_networks(link, nets, router):
    own = {}
    rb = {band_id(b.get("id") or b.get("band")): b for b in (router or {}).get("bands", [])}
    names = {b.get("ssid") for b in rb.values() if b.get("ssid")} | ({link["ssid"]} if link.get("ssid") else set())
    visible = any(n.get("ssid") for n in nets)
    lb = link["band"]
    own[lb] = {"channel": link["channel"], "width": link["width"], "seen": link["signal"], "phy": link.get("phy"), "security": link.get("security"), "inferred": False}
    for n in nets:
        n["mine"] = False
    if visible and names:
        for n in nets:
            if n.get("ssid") in names or (link.get("bssid") and n.get("bssid") == link["bssid"]):
                n["mine"] = True
        for b in ("2g", "5g", "6g"):
            if b == lb:
                continue
            mine = sorted((n for n in nets if n["mine"] and n["band"] == b), key=lambda n: -n["signal"])
            if mine:
                own[b] = {"channel": mine[0]["channel"], "width": mine[0]["width"], "seen": mine[0]["signal"], "phy": mine[0].get("phy"), "security": mine[0].get("security"), "inferred": False}
        return own
    for n in nets:
        if n["band"] == lb and n["channel"] == link["channel"] and n["width"] == link["width"] and abs(n["signal"] - link["signal"]) <= 6:
            n["mine"] = True
    other = "2g" if lb != "2g" else "5g"
    cfg = rb.get(other)
    if cfg and cfg.get("enabled") is False:
        return own
    cand = sorted((n for n in nets if n["band"] == other), key=lambda n: -n["signal"])
    fixed = cfg.get("channel") if cfg and isinstance(cfg.get("channel"), int) else None
    if fixed:
        cand = [n for n in cand if n["channel"] == fixed]
    lo, hi = (link["signal"] - 6, link["signal"] + 30) if other == "2g" else (link["signal"] - 30, link["signal"] + 6)
    if cand and lo <= cand[0]["signal"] <= hi and (fixed or len(cand) == 1 or cand[0]["signal"] - cand[1]["signal"] >= 6):
        c = cand[0]
        c["mine"] = True
        own[other] = {"channel": c["channel"], "width": c["width"], "seen": c["signal"], "phy": c.get("phy"), "security": c.get("security"), "inferred": True}
    return own


def best_channel(band, cur, neigh):
    def load(ch, w):
        return sum(10 ** (n["signal"] / 10) for n in neigh if overlaps(band, ch, w, n["channel"], n["width"]))

    def count(ch, w):
        return sum(1 for n in neigh if overlaps(band, ch, w, n["channel"], n["width"]))

    if band == "2g":
        w, cands = 20, [1, 6, 11]
    elif band == "5g":
        w = cur["width"] if cur["width"] in (20, 40, 80) else 80
        cands = {20: [36, 40, 44, 48, 149, 153, 157, 161, 165], 40: [36, 44, 149, 157], 80: [36, 149]}[w]
    else:
        return None
    def points(ch, w_):
        return sum(POINTS[n["level"]] for n in neigh if overlaps(band, ch, w_, n["channel"], n["width"]))

    here, p_here = load(cur["channel"], cur["width"]), points(cur["channel"], cur["width"])
    best = min(cands, key=lambda c: (points(c, w), load(c, w), abs(c - cur["channel"])))
    there, p_there = load(best, w), points(best, w)
    gain = 10 * math.log10(here / there) if here > 0 and there > 0 else (99 if here > 0 else 0)
    same = center(band, best, w) == center(band, cur["channel"], cur["width"]) and w == cur["width"]
    return {"channel": best, "width": w, "change": bool(not same and (p_there < p_here or (p_there == p_here and gain >= 3))), "overlap": count(best, w)}


def fmt_time(iso):
    try:
        t = datetime.datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return ""
    return f"{t.day} {t.strftime('%b').upper()} {t.year} · {t.strftime('%H:%M')}"


def dbm(v):
    return f"{v} dBm".replace("-", "−")


def analyze(scan, router=None, plan=None):
    link = scan.get("link")
    if not link:
        sys.exit("The scan has no Wi-Fi link, so there is nothing to draw. Connect this computer to Wi-Fi and scan again.")
    me = scan.get("self") or "This computer"
    here = me[0].lower() + me[1:]
    limits = list(scan.get("notes") or [])
    nets = [dict(n) for n in scan.get("networks") or [] if n.get("band") in BAND]
    own = own_networks(link, nets, router)
    rb = {band_id(b.get("id") or b.get("band")): b for b in (router or {}).get("bands", [])}

    bands = []
    for b in ("2g", "5g", "6g"):
        if b not in own:
            continue
        o, cfg = own[b], rb.get(b, {})
        bands.append({"id": b, "label": BAND[b], "channel": o["channel"], "width": o["width"], "seen": o["seen"],
                      "security": cfg.get("security") or o.get("security"), "standard": standard(o.get("phy"), b, cfg.get("mode")),
                      "power": cfg.get("power"), "auto": str(cfg.get("channel", "")).lower() == "auto" if cfg else None, "inferred": o["inferred"]})
    hidden = bool(nets) and not any(n.get("ssid") for n in nets)
    cant = []
    if hidden:
        cant.append("network names (the system hides them)")
        limits.append("If you have a mesh system or an extender, its other units can be counted as neighbours, because names are hidden.")
    for b in bands:
        if b["inferred"]:
            cant.append(f"which {b['label']} network is yours for certain (picked by signal strength)")
            limits.append(f"Your {b['label']} network was picked out by signal strength, because network names are hidden. "
                          f"If that pick is wrong, the {b['label']} overlap count is wrong too.")
    if not router:
        cant.append("device names, and phones that were asleep (needs the router login)")

    neigh = []
    for n in nets:
        if n["mine"]:
            continue
        o = own.get(n["band"])
        neigh.append({"name": n.get("ssid"), "band": n["band"], "channel": n["channel"], "width": n["width"], "signal": n["signal"],
                      "hit": bool(o and overlaps(n["band"], o["channel"], o["width"], n["channel"], n["width"])), "level": level_of(n["signal"])})
    neigh.sort(key=lambda n: (n["band"], n["channel"], -n["signal"]))

    interference, best = {"2g": None, "5g": None}, {}
    for b in ("2g", "5g"):
        if b not in own:
            continue
        inband = [n for n in neigh if n["band"] == b]
        hit = [n for n in inband if n["hit"]]
        pts = sum(POINTS[n["level"]] for n in hit)
        lvl = "none" if not hit else "low" if pts <= 1 else "medium" if pts <= 4 else "high"
        interference[b] = {"level": lvl, "overlap": len(hit), "total": len(inband), "strongest": max((n["signal"] for n in hit), default=None),
                           "loud": sum(1 for n in hit if n["level"] == "strong")}
        bc = best_channel(b, own[b], inband)
        if bc:
            best[b] = bc
    known = [interference[b]["level"] for b in ("2g", "5g") if interference[b]]
    interference["overall"] = max(known, key=LEVELS.index) if known else None

    host, gw = scan.get("host") or {}, scan.get("gateway") or {}
    devices, seen = [], set()

    def add(name, mac, ip, band, signal, rate, since, online, is_me, vendor, source):
        mac = norm_mac(mac) if mac else None
        key = mac or ip
        if key in seen:
            return
        seen.add(key)
        vendor = vendor or vendor_of(mac) or brand_from_name(name)
        text = f"{name or ''} {vendor or ''}"
        if is_me:
            label, kind = me, "laptop"
        else:
            label = name or (f"{vendor} device" if vendor else f"Device ·{ip.split('.')[-1]}" if ip else "Unnamed device")
            kind = kind_of(text)
        devices.append({"name": name, "label": label, "vendor": vendor, "kind": kind, "band": band, "signal": signal, "rate": rate, "ip": ip, "mac": mac,
                        "private": is_private_mac(mac), "since": since, "me": is_me, "online": online, "source": source})

    scanned = {d.get("mac") or d.get("ip"): d for d in scan.get("devices") or []}
    my_mac = next((d.get("mac") for d in scan.get("devices") or [] if d.get("me")), None)
    for c in (router or {}).get("clients", []):
        mac = norm_mac(c.get("mac")) if c.get("mac") else None
        is_me = bool((mac and mac == my_mac) or (c.get("ip") and c.get("ip") == host.get("ip") and c.get("online", True)))
        s = scanned.get(mac) or {}
        add(c.get("name"), mac, c.get("ip"), band_id(c.get("band")) or (link["band"] if is_me else None), link["signal"] if is_me else c.get("signal"), c.get("txRate") or c.get("rate"),
            c.get("connectedFor"), c.get("online", True), is_me, c.get("vendor") or s.get("vendor"), "router")
    for d in scan.get("devices") or []:
        add(d.get("name"), d.get("mac"), d.get("ip"), link["band"] if d.get("me") else None, link["signal"] if d.get("me") else None,
            link.get("rate") if d.get("me") else None, None, True, bool(d.get("me")), d.get("vendor"), "scan")
    if not any(d["me"] for d in devices):
        add(None, None, host.get("ip"), link["band"], link["signal"], link.get("rate"), None, True, True, None, "scan")
    devices.sort(key=lambda d: (not d["me"], not d["online"], (d["label"] or "").lower()))
    for i, d in enumerate(devices):
        d["id"] = f"d{i + 1}"
    online = [d for d in devices if d["online"]]
    offline = [d for d in devices if not d["online"]]

    speed = None
    if scan.get("speed"):
        s = scan["speed"]
        gap = (s["loaded"] - s["idle"]) if s.get("loaded") is not None and s.get("idle") is not None else None
        speed = {"down": s["down"], "up": s["up"], "plan": plan, "idle": s.get("idle"), "loaded": s.get("loaded"),
                 "lag": None if gap is None else "heavy" if gap >= 100 else "some" if gap >= 40 else "steady"}
        if s.get("method") == "http":
            limits.append("Speed was measured with a simple download and upload test, so treat the numbers as approximate.")

    r = router or {}
    wan = r.get("wanIp")
    cgnat = False
    if wan:
        try:
            cgnat = ipaddress.ip_address(wan) in ipaddress.ip_network("100.64.0.0/10")
        except ValueError:
            cgnat = False
    brand = r.get("brand") or gw.get("brand") or brand_in(gw.get("vendor") or "") or gw.get("vendor")
    rname = r.get("model") or gw.get("model") or (f"{brand} router" if brand else "Your router")
    ssid = next((rb[b].get("ssid") for b in ("5g", "2g") if rb.get(b, {}).get("ssid")), None) or link.get("ssid")
    if ssid and rb.get("2g", {}).get("ssid") and rb.get("5g", {}).get("ssid"):
        ssid = rb["2g"]["ssid"] if len(rb["2g"]["ssid"]) <= len(rb["5g"]["ssid"]) else rb["5g"]["ssid"]
    router_out = {"name": rname, "model": r.get("model") or gw.get("model"), "brand": brand, "hardware": r.get("hardware"), "firmware": r.get("firmware"),
                  "lanIp": gw.get("ip") or host.get("gateway"), "wanIp": wan, "cgnat": cgnat, "connection": r.get("connection"), "dhcp": r.get("dhcp"),
                  "dns": r.get("dns"), "qos": r.get("qos"), "uptime": r.get("uptime"), "bands": bands}

    F, score = [], 100.0

    def find(sev, title, detail, fix, tag, head=None, cost=0):
        nonlocal score
        F.append({"sev": sev, "title": title, "detail": detail, "fix": fix, "tag": tag, "head": head})
        score -= cost

    sec = (link.get("security") or "").lower()
    if sec.startswith("open") and "encrypted" not in sec:
        find("high", "Your Wi-Fi has no password", "Anyone in range can join it and watch traffic that is not encrypted.",
             "Turn on WPA2 or WPA3 with a strong password in the router's wireless settings", "Do this first", "Your Wi-Fi has no password.", 30)
    elif sec in ("wep", "wpa", "wpa/wpa2"):
        find("med", "Old Wi-Fi security", f"The network uses {link['security']}, which is easier to break than WPA2 or WPA3.",
             "Set security to WPA2 (AES) or WPA3 in the router's wireless settings", "1 setting", None, 5 if sec == "wpa/wpa2" else 20)

    caveat = " This rating counts how many networks overlap and how loud they are. It cannot see how busy they are."
    for b in bands:
        it = interference.get(b["id"])
        if not it:
            continue
        lab, ch, bc = b["label"], b["channel"], best.get(b["id"])
        used = b["id"] == link["band"] or not router or any(d["band"] == b["id"] for d in online)
        k = 1 if used else .5
        auto = " The router picks the channel itself (Auto), so it can move again." if b["auto"] else ""
        move = (f"Set {lab} to channel {bc['channel']} at {bc['width']} MHz in the router's wireless settings. "
                f"{bc['overlap']} network{' overlaps' if bc['overlap'] == 1 else 's overlap'} there instead of {it['overlap']}" if bc and bc["change"] else None)
        if it["level"] == "high":
            find("high", f"{lab} channel is crowded",
                 f"{it['overlap']} of {it['total']} nearby networks overlap your channel {ch}, and {it['loud']} of them are loud (strongest {dbm(it['strongest'])}). "
                 f"Your devices have to take turns with them.{caveat}{auto}",
                 move or "No clearer channel is free on this band. Keep phones and laptops on 5 GHz where you can", "1 setting" if move else "Limit",
                 f"Your {lab} channel is crowded: {it['overlap']} nearby networks overlap it.", 22 * k)
        elif it["level"] == "medium":
            find("med", f"Neighbours share your {lab} channel",
                 f"{it['overlap']} of {it['total']} nearby networks overlap your channel {ch} (strongest {dbm(it['strongest'])}).{caveat}{auto}",
                 move or "No clearer channel is free on this band right now", "1 setting" if move else "Limit",
                 f"A few neighbours share your {lab} channel.", 12 * k)
        elif it["level"] == "low":
            odd = b["id"] == "2g" and ch not in (1, 6, 11)
            find("low", f"{lab}: neighbours overlap, but faintly",
                 f"{it['overlap']} of {it['total']} nearby networks overlap your channel {ch}. The strongest is {dbm(it['strongest'])}, "
                 f"around or below the level where your router has to wait for it, so the effect is small.{auto}",
                 (f"Optional: channel {bc['channel']} is the standard slot with the least overlap" if odd and bc and bc["change"] else "Nothing to change"), "Minor", None, 3 * k)
        else:
            find("good", f"{lab} channel is clear", f"No other network overlaps channel {ch} at {b['width']} MHz."
                 + (f" {it['total']} other {lab} network{' is' if it['total'] == 1 else 's are'} nearby, on {'another channel' if it['total'] == 1 else 'other channels'}." if it["total"] else ""), None, "OK")
        if b["id"] == "2g" and b["width"] >= 40:
            find("med", "2.4 GHz is set too wide", "At 40 MHz it covers most of the 2.4 GHz band, so it overlaps almost every neighbour and picks up more noise.",
                 "Set the 2.4 GHz channel width to 20 MHz", "1 setting", None, 4)

    sig, noise = link["signal"], link.get("noise")
    if sig <= -75:
        find("high", f"Weak signal where {here} sits", f"The signal here is {dbm(sig)}. Below about −75 dBm, speed drops sharply and calls break up.",
             "Move closer, or put the router in a central, raised, open spot. A mesh unit helps; a single-band repeater roughly halves speed", "Placement",
             f"The signal is weak where {here} sits.", 18)
    elif sig <= -67:
        find("med", f"Signal is borderline where {here} sits", f"The signal here is {dbm(sig)}. That is fine for browsing and borderline for video calls.",
             "Move a little closer to the router, or raise the router and clear things from around it", "Placement", f"The signal is borderline where {here} sits.", 8)
    if noise is not None and sig - noise < 20:
        find("med", "Noisy spot", f"The signal is only {sig - noise} dB above the background noise. About 20 dB is needed for steady data and 25 dB for calls.",
             "Move away from microwaves, cordless phones and Bluetooth clutter, or switch this device to 5 GHz", "Placement", None, 8)

    if speed and speed["lag"] == "heavy":
        qos_off = bool(re.search(r"off|disabled", str(r.get("qos") or ""), re.I))
        find("med", "Lag rises when the line is busy",
             f"Ping is {speed['idle']} ms when the line is idle and about {speed['loaded']} ms during a heavy download. Calls and games can stutter while someone else downloads.",
             ("QoS is off in your router. Turning it on can help, but on some routers it lowers top speed, so scan again after changing it" if qos_off
              else "Look for QoS or Smart Queue in the router settings, and scan again after changing it"), "You decide", "Lag rises when the line is busy.", 12)
    elif speed and speed["lag"] == "some":
        find("low", "A little lag under load", f"Ping goes from {speed['idle']} ms idle to about {speed['loaded']} ms during a heavy download.", "Nothing to change unless calls stutter", "Minor", None, 5)
    elif speed and speed["lag"] == "steady":
        find("good", "Ping stays steady under load", f"{speed['idle']} ms idle and {speed['loaded']} ms during a heavy download.", None, "OK")

    if speed and plan:
        pct = round(speed["down"] / plan * 100)
        if pct < 50:
            why = "The signal where you sit is one likely reason, so test again next to the router" if sig <= -67 else "Test once with a cable plugged into the router. If that is also slow, the line or the plan is the limit, so call the provider"
            find("med", f"You get {pct}% of your plan", f"The test measured {speed['down']} Mbps on a {plan} Mbps plan.", why, "Check", f"You get {pct}% of the speed you pay for.", 12)
        elif pct >= 80:
            find("good", "Speed matches your plan", f"The test measured {speed['down']} Mbps on a {plan} Mbps plan.", None, "OK")

    if router:
        find("info", f"{len(online)} devices online" + (f", {len(offline)} more remembered" if offline else ""),
             "Tick the devices you know in the list on the left. A phone using a private address shows a generic name, so check by counting your own devices.",
             "If one is not yours, change the Wi-Fi password. Every device then has to join again", "Check")
    else:
        find("info", "Device names need the router login", f"The scan found {len(online)} devices by address only, and sleeping phones can be missed.",
             "Log in to the router and run the skill again to get names, bands and link speeds", "Optional")
    if cgnat:
        find("info", "Internet address is shared by the provider",
             "The router's public address starts with 100, which means the provider shares one address among many homes. It does not slow you down, but port forwarding and hosting a game server will not work.",
             "Ask the provider for a public IP only if you need one", "Info")

    todo = next((f["fix"] for f in F if f["sev"] in ("high", "med") and f["fix"]), None)
    if limits:
        find("info", "What this scan could not see", " ".join(limits), None, "Limits")
    rank = {"high": 0, "med": 1, "low": 2, "info": 3, "good": 4}
    F.sort(key=lambda f: rank[f["sev"]])
    score = max(5, min(99, round(score)))
    heads = [f["head"] for f in F if f["head"]]
    if score >= 80:
        headline = "Your Wi-Fi is healthy." + (f" {heads[0]}" if heads else "")
    elif heads:
        headline = " ".join(heads[:2])
    else:
        headline = "Your Wi-Fi works, with a few small things to tidy up."
    for f in F:
        del f["head"]

    return {"meta": {"scannedAt": fmt_time(scan.get("scannedAt")), "platform": scan.get("platform"), "self": me, "routerLogin": bool(router),
                     "namesHidden": bool(nets) and not any(n.get("ssid") for n in nets), "version": VERSION},
            "ssid": ssid, "router": router_out,
            "link": {k: link.get(k) for k in ("band", "channel", "width", "signal", "noise", "rate", "mcs", "phy", "streams")},
            "speed": speed, "devices": devices, "neighbors": neigh, "interference": interference, "best": best,
            "score": score, "headline": headline, "findings": F, "limits": limits, "cant": cant, "todo": todo}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cmd_build(a):
    scan_path = os.path.join(a.out, "scan.json")
    if not os.path.exists(scan_path):
        sys.exit(f"No scan.json in {a.out}. Run the scan step first.")
    router_path = a.router or os.path.join(a.out, "router.json")
    router = load_json(router_path) if os.path.exists(router_path) else None
    report = analyze(load_json(scan_path), router, a.plan)
    with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)
    with open(TEMPLATE, encoding="utf-8") as f:
        page = f.read()
    data = json.dumps(report, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    title = f"Wi-Fi X-ray · {report['ssid'] or 'network scan'}"
    page = page.replace("__TITLE__", html.escape(title)).replace("__DATA__", data)
    out = os.path.join(a.out, "wifi-xray.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)

    it, sp = report["interference"], report["speed"]
    on = [d for d in report["devices"] if d["online"]]
    off = len(report["devices"]) - len(on)
    if a.details:
        for f_ in report["findings"]:
            say(f"Finding [{f_['sev']}]  {f_['title']}: {f_['detail']}" + (f" -> {f_['fix']}" if f_["fix"] else ""))
        say("")
    say("SHORT SUMMARY. Give the person these lines and nothing longer:")
    say(f"Health: {report['score']}/100. {report['headline']}")
    say(f"On your Wi-Fi: {len(on)} devices online" + (f", {off} more remembered by the router" if off else "") + ("" if router else ", by address only (no router login)"))
    parts = [f"{BAND[b]} {it[b]['level']} ({it[b]['overlap']} of {it[b]['total']} nearby networks overlap" + (f", strongest {it[b]['strongest']} dBm)" if it[b]["strongest"] is not None else ")")
             for b in ("2g", "5g") if it.get(b)]
    say("Neighbour interference: " + ("; ".join(parts) if parts else "not measured"))
    if sp:
        say(f"Speed: {sp['down']} Mbps down, {sp['up']} Mbps up" + (f". Ping {sp['idle']} ms idle, {sp['loaded']} ms busy" if sp.get("loaded") is not None else ""))
    if report["todo"]:
        say(f"Worth doing: {report['todo']}")
    if report["cant"]:
        say("Could not see: " + "; ".join(report["cant"]))
    say(f"Page: {os.path.abspath(out)}")
    say("Everything else, including each finding and the full list of limits, is on the page and in report.json.")
    if a.open:
        webbrowser.open("file://" + os.path.abspath(out))


MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}\b")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HEADER_RE = re.compile(r"^(device( info| name| type)?|host ?name|mac address|ip( address)?|operation|speed limit|duration|status|online|offline|"
                       r"connected (clients?|devices?)|view blacklist|real-time rate|tx/rx rate.*|name|type|band|signal|action|block|edit|support|back to top|"
                       r"clients?|wired|wireless|interface|lease time|connection type)$", re.I)
BAND_RE = re.compile(r"^(2\.4\s*G(Hz)?|5\s*G(Hz)?|6\s*G(Hz)?|wired|ethernet|lan|cable)$", re.I)


def clipboard():
    if OS == "mac":
        return run(["pbpaste"], 10)
    if OS == "win":
        return run(["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"], 15)
    return run(["wl-paste"], 10) or run(["xclip", "-selection", "clipboard", "-o"], 10)


def redact(text):
    out, hide = [], False
    for line in text.splitlines():
        if hide and line.strip():
            out.append("[hidden]")
            hide = False
            continue
        m = re.search(r"(pass(word|phrase|key)?|pre-?shared key|\bpsk\b|\bpin\b)\s*[:=]?\s*(.*)$", line, re.I)
        if m and m.group(3).strip():
            out.append(line[:m.start(3)] + "[hidden]")
        else:
            out.append(line)
            hide = bool(m)
    return "\n".join(out)


def is_noise(s):
    return bool(not s or len(s) > 48 or MAC_RE.search(s) or IP_RE.fullmatch(s) or HEADER_RE.match(s) or BAND_RE.match(s)
                or re.fullmatch(r"[-–—\d\s./:%]+", s) or re.fullmatch(r"[\d.]+\s*[kmg]?bps", s, re.I) or re.fullmatch(r"-?\d+\s*dBm", s, re.I))


def read_clients(text):
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    idx = [i for i, x in enumerate(lines) if MAC_RE.search(x)]
    clients = []
    for n, i in enumerate(idx):
        end = idx[n + 1] if n + 1 < len(idx) else min(len(lines), i + 12)
        cells = [c.strip() for c in re.split(r"\t+|\s{2,}", lines[i]) if c.strip()]
        block = cells + lines[i + 1:end]
        name = next((c for c in cells if not is_noise(c)), None) or next((b for b in reversed(lines[max(0, i - 2):i]) if not is_noise(b)), None)
        ip = next((m.group() for b in block for m in [IP_RE.search(b)] if m and not m.group().startswith("255.")), None)
        rate = next((m for b in block if not MAC_RE.search(b) and not IP_RE.search(b) for m in [re.search(r"\b(\d{1,4})\s*/\s*(\d{1,4})\b", b)] if m), None)
        since = next((b for b in block if re.fullmatch(r"\d+\s*(s|secs?|min|mins|minutes?|h|hrs?|hours?|d|days?)(\s+\d+\s*\w+)*", b, re.I)), None)
        band = next((band_id(b) for b in block if BAND_RE.match(b)), None)
        sig = next((int(m.group(1)) for b in block for m in [re.fullmatch(r"(-\d{2})\s*dBm", b, re.I)] if m), None)
        dashes = sum(1 for b in block if re.fullmatch(r"-{2,}", b))
        online = not any(re.fullmatch(r"offline|disconnected", b, re.I) for b in block) and not (dashes >= 3 and not rate)
        c = {"name": name, "mac": norm_mac(MAC_RE.search(lines[i]).group()), "ip": ip, "online": online}
        if online:
            c.update({k: v for k, v in (("band", band), ("signal", sig), ("txRate", int(rate.group(1)) if rate else None),
                                         ("rxRate", int(rate.group(2)) if rate else None), ("connectedFor", since)) if v is not None})
        clients.append(c)
    out = {"clients": clients}
    model = re.search(r"\b(Archer\s+[A-Z]{1,3}\d{1,4}\w*|TL-[A-Z0-9]{4,}|DIR-\d{3,4}\w*|RT-[A-Z]{1,3}\d{2,4}\w*)\b", text)
    if model:
        out["model"] = ("TP-Link " if re.match(r"Archer|TL-", model.group(1)) else "") + model.group(1)
    wan = re.search(r"(?:internet|wan|public) ip[^\n]*?[:\n]\s*(\d{1,3}(?:\.\d{1,3}){3})", text, re.I)
    if wan:
        out["wanIp"] = wan.group(1)
    return out


def cmd_clip(a):
    if a.from_file:
        with open(a.from_file, encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        text = clipboard()
    if len({norm_mac(m) for m in MAC_RE.findall(text or "")}) < 1:
        sys.exit("What was copied does not look like a router's device list (it has no hardware addresses), so nothing was saved. "
                 "Ask the person to open the list of connected devices in the router page, press Select All, then Copy, and try again.")
    os.makedirs(a.out, exist_ok=True)
    text = redact(text)
    with open(os.path.join(a.out, "router-page.txt"), "w", encoding="utf-8") as f:
        f.write(text)
    draft = read_clients(text)
    with open(os.path.join(a.out, "router.json"), "w", encoding="utf-8") as f:
        json.dump(draft, f, indent=1, ensure_ascii=False)
    on = [c for c in draft["clients"] if c["online"]]
    say(f"Read {len(draft['clients'])} devices from the copied page: {len(on)} online, {len(draft['clients']) - len(on)} not connected now."
        + (f" Router: {draft['model']}." if draft.get("model") else ""))
    for c in draft["clients"]:
        say(f"  {'online ' if c['online'] else 'earlier'}  {c.get('name') or '(no name)':<28} {c.get('ip') or '':<15} {c.get('band') or '':<5} {str(c.get('txRate') or ''):<5} {c.get('connectedFor') or ''}")
    say(f"\nSaved router.json (a first-pass reading) and router-page.txt (the copied text) in {a.out}.")
    say("Compare the two, correct anything the first pass got wrong in router.json, then run build.")


def cmd_login(a):
    path = os.path.join(a.out, "scan.json")
    scan = load_json(path) if os.path.exists(path) else {}
    ip = (scan.get("gateway") or {}).get("ip") or (scan.get("host") or {}).get("gateway")
    if not ip:
        sys.exit(f"No router address in {a.out}. Run the scan step first.")
    url = f"http://{ip}/"
    if not a.no_open:
        webbrowser.open(url)
    say(f"Router login page: {url}")


def cmd_demo(a):
    os.makedirs(a.out, exist_ok=True)
    for name in ("scan.json", "router.json"):
        with open(os.path.join(EXAMPLE, name), encoding="utf-8") as src, open(os.path.join(a.out, name), "w", encoding="utf-8") as dst:
            dst.write(src.read())
    a.router, a.plan, a.details = None, 100, False
    cmd_build(a)


def find_browser():
    if OS == "mac":
        c = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
             "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser", "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    elif OS == "win":
        roots = [os.environ.get(k, "") for k in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")]
        c = [os.path.join(r, p) for r in roots if r for p in (r"Google\Chrome\Application\chrome.exe", r"Microsoft\Edge\Application\msedge.exe")]
    else:
        c = ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"]
    return next((p for p in c if os.path.exists(p)), None)


def cmd_check(a):
    page = os.path.join(a.out, "wifi-xray.html")
    if not os.path.exists(page):
        sys.exit(f"No wifi-xray.html in {a.out}. Run the build step first.")
    exe = find_browser()
    if not exe:
        sys.exit("No Chrome-family browser found, so no screenshot was taken. Open the page yourself to check it.")
    shot = os.path.abspath(os.path.join(a.out, "check.png"))
    url = "file://" + os.path.abspath(page).replace("\\", "/") + "?skip" + ("&privacy" if a.privacy else "")
    run([exe, "--headless=new", "--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--hide-scrollbars", "--window-size=1440,900",
         "--force-device-scale-factor=1", "--virtual-time-budget=9000", f"--screenshot={shot}", url], 120)
    say(f"Screenshot: {shot}" if os.path.exists(shot) else "The browser did not produce a screenshot.")


def main():
    p = argparse.ArgumentParser(prog="wifixray", description="Scan the Wi-Fi network this computer is on and build the Wi-Fi X-ray page. Read-only: it never changes a setting.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="read the Wi-Fi link, nearby networks, speed and devices into scan.json")
    s.add_argument("--out", default="wifi-xray-report")
    s.add_argument("--no-speed", action="store_true", help="skip the speed and lag test")
    s.add_argument("--no-devices", action="store_true", help="do not ping the network for devices")
    s.add_argument("--big-network", action="store_true", help="search for devices even though the network is larger than a home network")
    s.add_argument("--replay", action="store_true", help="re-read the saved raw captures in <out>/raw instead of scanning")
    s.set_defaults(fn=cmd_scan)
    b = sub.add_parser("build", help="turn scan.json (and router.json, if present) into wifi-xray.html")
    b.add_argument("--out", default="wifi-xray-report")
    b.add_argument("--router", help="path to router.json (default: <out>/router.json)")
    b.add_argument("--plan", type=float, help="the internet plan's download speed in Mbps")
    b.add_argument("--open", action="store_true", help="open the page in the default browser")
    b.add_argument("--details", action="store_true", help="also print every finding in full")
    b.set_defaults(fn=cmd_build)
    g = sub.add_parser("login", help="open the router's login page in the default browser and print its address")
    g.add_argument("--out", default="wifi-xray-report")
    g.add_argument("--no-open", action="store_true", help="only print the address")
    g.set_defaults(fn=cmd_login)
    k = sub.add_parser("clip", help="read the router's device list that the person copied, and write router.json")
    k.add_argument("--out", default="wifi-xray-report")
    k.add_argument("--from", dest="from_file", help="read the copied text from this file instead of the clipboard")
    k.set_defaults(fn=cmd_clip)
    d = sub.add_parser("demo", help="build the page from the bundled sample network")
    d.add_argument("--out", default="wifi-xray-demo")
    d.add_argument("--open", action="store_true")
    d.set_defaults(fn=cmd_demo)
    c = sub.add_parser("check", help="screenshot the built page with a Chrome-family browser")
    c.add_argument("--out", default="wifi-xray-report")
    c.add_argument("--privacy", action="store_true", help="take the screenshot with names and addresses hidden")
    c.set_defaults(fn=cmd_check)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
