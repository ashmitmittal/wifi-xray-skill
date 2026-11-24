# Data format

Three JSON files live in the report folder. The engine writes `scan.json` and `report.json`. You write `router.json`, and `scan.json` too when the engine cannot run on the person's system.

Leave a field out, or set it to `null`, when you did not measure or see it. Never fill a gap with a guess; the page copes with missing values and says what is missing.

## scan.json

What this computer could measure by itself.

```json
{
  "version": 1,
  "scannedAt": "2026-11-23T22:05:09+05:30",
  "platform": "macOS 27.2.1",
  "self": "This Mac",
  "host": {"ip": "192.168.0.106", "mask": "255.255.255.0", "gateway": "192.168.0.1", "iface": "en0"},
  "gateway": {"ip": "192.168.0.1", "mac": "50:C7:BF:10:20:30", "vendor": "TP-Link", "brand": "TP-Link", "model": null},
  "link": {"ssid": null, "band": "5g", "channel": 161, "width": 80, "signal": -54, "noise": -90,
           "rate": 390, "mcs": 4, "phy": "802.11ac", "streams": 2, "security": "WPA2-Personal"},
  "networks": [
    {"ssid": null, "band": "2g", "channel": 6, "width": 20, "signal": -78, "phy": "802.11b/g/n", "security": "WPA2-Personal"}
  ],
  "speed": {"down": 240.7, "up": 238.4, "idle": 33, "loaded": 228, "rpm": 263, "method": "networkQuality"},
  "devices": [
    {"ip": "192.168.0.106", "mac": "A2:11:22:33:44:01", "name": null, "vendor": null, "private": true, "me": true}
  ],
  "notes": ["Anything the reader should know about gaps in this scan."]
}
```

| Field | Meaning |
| --- | --- |
| `self` | What to call this computer on the page: "This Mac", "This PC". |
| `link` | The connection this computer has right now. `band` is `2g`, `5g` or `6g`. `signal` and `noise` are in dBm (negative numbers). `rate` is the link rate in Mbps. `ssid` is `null` when the system hides it. |
| `networks` | Every other network in range, including the person's own router on its other band. One entry per access point. `width` is the channel width in MHz. |
| `speed` | `down` and `up` in Mbps. `idle` is ping in ms with the line quiet; `loaded` is ping during a heavy transfer. |
| `devices` | What answered on the local network. `private` is true when the hardware address is a randomised one (second hex digit is 2, 6, A or E). Mark this computer with `"me": true`. Do not list the router here. |
| `notes` | Plain sentences about what the scan could not do. They are shown to the person as limits. |

### Collecting the readings by hand

When the engine cannot run, these are the commands it would have used.

macOS (no admin rights needed):

- `system_profiler SPAirPortDataType -json`: the link and the nearby networks.
- `networkQuality -c`: speed, responsiveness (round trips per minute; loaded ping is 60000 divided by it) and base round-trip time.
- `route -n get default`, `ipconfig getifaddr en0`, `ipconfig getoption en0 subnet_mask`: addresses.
- `arp -an` after one ping to each address of the home network: devices.

Windows:

- `netsh wlan show interfaces` and `netsh wlan show networks mode=bssid`: the link and nearby networks. Signal is a percentage; dBm is roughly half of it minus 100. Windows 11 24H2 needs Location services switched on for these.
- `ipconfig` and `arp -a`: addresses and devices.

Linux: `nmcli -f ALL dev wifi list`, `ip route`, `ip neigh`.

## router.json

What the router's own admin page says. Everything is optional.

```json
{
  "model": "TP-Link Archer C6",
  "hardware": "v3.2",
  "firmware": "1.3.6 Build 20250412",
  "connection": "PPPoE",
  "wanIp": "100.64.0.10",
  "dhcp": "192.168.0.100 – .249",
  "dns": "ISP automatic",
  "qos": "Off",
  "uptime": "12d 04h",
  "bands": [
    {"id": "2g", "ssid": "MyHome", "channel": "auto", "width": "auto", "security": "WPA2-Personal",
     "mode": "802.11b/g/n", "power": "High", "enabled": true},
    {"id": "5g", "ssid": "MyHome_5G", "channel": 36, "width": 80, "security": "WPA2-Personal",
     "mode": "802.11a/n/ac", "power": "High", "enabled": true}
  ],
  "clients": [
    {"name": "iPhone", "mac": "A2:11:22:33:44:02", "ip": "192.168.0.107", "band": "5g",
     "signal": null, "txRate": 585, "connectedFor": "39 min", "online": true},
    {"name": "Pixel-8", "mac": "A2:11:22:33:44:03", "ip": "192.168.0.100", "online": false}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `bands[].channel` | A number when the router is set to a fixed channel, or `"auto"`. With a number, the engine uses it to find the person's own network on that band. With `"auto"`, it picks the network out by signal strength and marks the result as inferred. |
| `bands[].ssid` | The network name. Used to match the person's own networks when names are visible, and shown on the page. |
| `clients[].band` | `"2g"`, `"5g"`, `"6g"` or `"wired"`. |
| `clients[].signal` | dBm, if the router shows it. Many do not; leave it out. |
| `clients[].txRate` | Link rate from the router to the device, in Mbps. |
| `clients[].online` | `false` for devices the router remembers that are not connected now. Defaults to `true`. |
| `clients[].vendor` | Only if the router page states the maker. Otherwise the engine works it out from the hardware address. |

Never put a Wi-Fi password or the router's admin password in this file.

## report.json

The analysed result that the page draws. The engine writes it; read it when you need a number for your summary.

- `interference.2g` / `interference.5g`: `level` (`none`, `low`, `medium`, `high`), `overlap` (networks that overlap the person's channel), `total` (networks on that band), `strongest` (dBm), `loud` (overlapping networks at −70 dBm or stronger). `null` when the person's network on that band was not found. `interference.overall` is the worse of the two.
- `neighbors[]`: each with `hit` (overlaps the person's channel) and `level` (`strong` at −70 dBm or more, `audible` down to −82, `faint` below).
- `best`: the least crowded standard channel per band. `change` is true only when that channel scores fewer interference points than the current one, or the same points with at least 3 dB less overlapping signal.
- `devices[]`: merged from the router and the scan. `source` says which. `label` is the name shown.
- `findings[]`: `sev` is `high`, `med`, `low`, `info` or `good`.
- `limits[]`: what this run could not see. Pass every one of them on.

### How the numbers are worked out

- **Overlap.** A 2.4 GHz network 20 MHz wide is treated as 22 MHz around its channel; a 40 MHz one is centred two channels up (channels 1 to 7) or two down. On 5 GHz, 40 and 80 MHz networks are placed on the standard bonded blocks. Two networks overlap when those ranges touch.
- **Interference points.** Among overlapping networks: 3 for each at −70 dBm or stronger, 1 for each between −70 and −82 dBm, 0 below that. 0 overlapping is `none`; up to 1 point is `low`; up to 4 is `medium`; more is `high`.
- **Best channel.** 2.4 GHz candidates are 1, 6 and 11 at 20 MHz. 5 GHz candidates keep the current width and avoid the radar (DFS) channels 52 to 144.
- **Lag.** `heavy` when loaded ping is 100 ms or more above idle ping, `some` from 40 ms, otherwise `steady`.
- **Health score.** Starts at 100. Interference: high −22, medium −12, low −3 per band, halved for a band no device is using. Heavy lag −12, some lag −5. Signal at −75 dBm or weaker −18, at −67 or weaker −8. Signal-to-noise under 20 dB −8. No password −30. 2.4 GHz at 40 MHz −4. Under half the plan's speed −12. Clamped to 5–99.
