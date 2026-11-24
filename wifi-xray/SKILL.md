---
name: wifi-xray
description: Scan the Wi-Fi network this computer is on and build an interactive 3D "X-ray" page of it. The page shows every device on the network around the router, which neighbouring networks sit on the same channel and how loud they are, real download and upload speed, lag under load, and a plain-language diagnosis. Use this skill whenever someone asks who or what is using their Wi-Fi, whether a neighbour's router is interfering, why their Wi-Fi or video calls are slow or laggy, which Wi-Fi channel to use, or wants to see, map, check, test or diagnose their home network ("why is my Wi-Fi slow", "is someone on my Wi-Fi", "scan my network", "check my router"), even when they don't say "scan". It is read-only and never changes a router setting.
---

# Wi-Fi X-ray

You turn "what is going on with my Wi-Fi?" into one HTML page the person can open and click through: a hologram of their network with the router in the middle, every device around it, the neighbours' networks as domes, a channel spectrum, speed and lag, and a short diagnosis.

The page answers two questions first, because they are what people actually want to know:

1. **Who is on my Wi-Fi?** Every device, with the ones the router remembers.
2. **Are my neighbours' routers interfering?** Which networks overlap the person's channel, and a low, medium or high rating.

The person may not be technical. The whole thing should feel like this: they ask, a page opens with the result, and one simple offer follows for the device names. Nothing else is asked of them.

The work is split in two:

- **The engine** (`scripts/wifixray.py` and `assets/template.html`) does the measuring, the overlap maths, the rating and the page. Do not rewrite it or hand-edit the page for one person. It is tested; fresh code written per run is not.
- **You** run the steps and talk to the person in a few plain lines.

## How to talk to the person

The page carries the detail. Your messages carry the headline and the next step.

- **Keep every message to about a dozen lines.** No long paragraphs, no walls of findings. If they want more, they will ask, and the page has it.
- **Plain words.** "Devices", "your router's page", "copy". Not "clients", "gateway", "MAC".
- **Put a link on its own numbered line, in bold**, so they can see where to click without reading.
- **Do not make them choose or configure anything** before they have seen a result.

## Rules that do not bend

- **Read-only.** This skill never changes a router setting, never restarts anything, and never touches the Wi-Fi name, the passwords or the firmware. If the person wants a change made, explain the steps and let them click.
- **Their own network only.** If it is not clear the network is theirs, ask once in one line before scanning. Do not scan an office, college, café or hotel network unless the person runs it. The engine also refuses to search for devices on a network larger than a home network.
- **Never ask for the router password.** The person types it into their own browser. You never see it.
- **Never promise speed.** Most slow Wi-Fi comes from distance, walls, an old router or the provider.
- **Never call a device an intruder.** The scan cannot know who owns a device.

## What it needs

- Commands must run on the person's **own computer**, on the Wi-Fi being checked: Claude Code in a terminal or in the desktop app's Code tab. In a cloud sandbox or a virtual machine the scan would describe the sandbox, not their home. If you cannot run local commands, say so and stop.
- Python 3.9 or newer. No packages to install. No browser tool or extension is needed.
- **On macOS, run every step with Apple's `/usr/bin/python3`** (it comes with the Xcode Command Line Tools). Python from Homebrew or python.org runs as a separate app, and macOS hides the other devices on the local network from it, so the device list comes back empty. If `/usr/bin/python3` is missing, use whatever Python there is; if the engine then reports that macOS blocked it, ask the person to allow "Python" under System Settings > Privacy & Security > Local Network. The first scan may also make macOS ask whether the terminal app may find devices on the local network; the person should allow it.
- On Windows use `python`. Windows support is written from the documented `netsh` output and has not been run on a real PC yet; say so in one line of your result message.
- Internet access for the speed test, for a one-time download of a public list of device makers (about 3 MB, cached), and for the page's fonts and 3D library when it is opened.

Below, `PY` stands for that Python and `<skill>` for this skill's folder.

## Workflow

Result first, names second. Work in a folder of its own, for example `./wifi-xray-report/`.

### 1. Scan

Say one line ("Scanning your Wi-Fi. About a minute, including a 20-second speed test."), then run:

```bash
PY <skill>/scripts/wifixray.py scan --out wifi-xray-report
```

It prints a short summary, any notes, and the router's address. Act on a note only if it blocks you:

- **"macOS did not let this copy of Python see the other devices"**: scan again with `/usr/bin/python3`.
- **"larger than a home network"**: the device search was skipped. Ask whether this really is their own network before running again with `--big-network`.
- **Windows "blocked the Wi-Fi scan"**: Location services are off. Give the person the setting it names and scan again.

`--no-speed` skips the speed test on metered connections. `--no-devices` skips the pings. If Python is missing or the system is neither macOS nor Windows, collect the readings with the system's own tools and write `scan.json` yourself; `references/data-format.md` lists every field.

### 2. Build the page and open it

Do this straight after the scan. Do not ask anything first.

```bash
PY <skill>/scripts/wifixray.py build --out wifi-xray-report --open
```

It opens the page in their browser and prints a **short summary** for you to pass on. Add `--plan 300` only if the person has already told you their plan's download speed in Mbps.

To confirm the page drew properly, `PY <skill>/scripts/wifixray.py check --out wifi-xray-report` saves `check.png` using a Chrome-family browser. Look at it once. Skip this if there is no such browser.

### 3. Give the result, then offer the device names

Send one message: the result in a few lines, then the offer. Fill in their numbers, their router's address from the scan, and the name their router uses for its device list (`references/router-read.md` lists it by brand; if you don't know, say "the list of connected devices"). On Windows the keys are Ctrl+A and Ctrl+C.

> **Wi-Fi X-ray: 73/100.** The page is open in your browser.
>
> - **On your Wi-Fi:** 7 devices, shown by address only for now.
> - **Neighbour interference:** 2.4 GHz medium (3 of 4 networks overlap yours), 5 GHz low.
> - **Speed:** 204 Mbps down, 132 up. Ping 11 ms idle, 200 ms when the line is busy.
> - **Worth doing:** set 2.4 GHz to channel 1 in your router's wireless settings.
>
> Couldn't see: network names (macOS hides them).
>
> **Want the real names of those 7 devices?** Your router knows them:
>
> 1. Open **→ http://192.168.0.1** and log in to your router.
> 2. Click **Clients** (the list of connected devices).
> 3. Press **Cmd+A**, then **Cmd+C**, and type **done** here.
>
> I only read what you copy. Nothing on your router changes.

Then stop and wait. If they don't want it, you are finished.

Wording to hold to: a device is "one I can't put a name to", never an intruder. A change "may help", never "will make it faster". Do not explain ratings, findings or method unless they ask.

### 4. When they say "done", add the names

```bash
PY <skill>/scripts/wifixray.py clip --out wifi-xray-report
```

This reads what they copied, saves it as `router-page.txt` and writes a first-pass `router.json`. It refuses, and saves nothing, if the copied text has no device list in it.

- If it refuses, they copied the wrong thing. Tell them in two lines: open the list of connected devices, click once on the page, Cmd+A, Cmd+C, then "done".
- Otherwise open `router-page.txt` and `router.json` side by side and correct `router.json` where the first pass misread it: a wrong or missing name, a device marked online that the page shows as disconnected, a band the page states. `references/router-read.md` shows what to look for and `references/data-format.md` has the fields. Add the router's model and public IP if the copied text shows them. Never copy a Wi-Fi password into the file.

Build again with the same command as step 2. The page reloads with names. Then send a short update and stop:

> **Updated.** 4 devices online and 6 more your router remembers, now with names. Tick the ones you know in the list on the left; anything left unticked is worth a second look.
>
> Press **P** on the page to hide names before you share or record it.

### If they want to fix something

The page says what to change; the person makes the change. Find the setting in their router's menus and describe the clicks. Suggest saving the router's settings first if it has a backup page. Change one thing, scan again, and compare. If nothing improved, say so and suggest putting it back.

## How to read the ratings

Use this only when the person asks what a rating means.

- **Loud, quiet, faint.** A neighbour at −70 dBm or stronger is loud. Between −70 and −82 dBm it is quieter but still makes the router wait its turn. Below −82 dBm, Wi-Fi devices mostly stop waiting for it, so it matters little.
- **Interference** per band comes from the overlapping networks only: 3 points for each loud one, 1 for each quieter one, 0 for faint. No overlap is "none", up to 1 point is "low", up to 4 is "medium", more is "high".
- The rating cannot see how busy a neighbour is. A loud but idle network costs little; a quiet one streaming all day costs more.
- **Health score** starts at 100 and loses points for interference, lag under load, weak signal, weak security and speed far below the plan. It is this skill's own summary number, not a standard.

`references/data-format.md` has the exact thresholds. The page lists what the scan could not see under "What this scan could not see".

## Files in the report folder

`scan.json`, `router-page.txt`, `router.json`, `report.json`, `wifi-xray.html`, `check.png` and `raw/` (the untouched command output). They contain device names, hardware addresses and the public IP, so the folder should not be posted or committed to a public repository. The page has a privacy mode for screenshots: press P, or add `?privacy` to its address.

`PY <skill>/scripts/wifixray.py demo --open` builds the page from a made-up network, which is handy for showing what the result looks like before scanning.
