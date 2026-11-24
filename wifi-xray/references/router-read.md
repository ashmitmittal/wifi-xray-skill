# Reading the router's device list

The router is the only place that knows every device's name and which ones were connected earlier. The person gets that list to you in the simplest way there is: they open the router's page, copy it, and you read the copy. No browser tool is needed, and you never see their password.

## What the person does

1. Opens the router's address (the one the scan printed, usually `http://192.168.0.1`, `http://192.168.1.1` or `http://192.168.29.1`) and logs in.
2. Opens the list of connected devices. The table below says what each brand calls it.
3. Clicks once on the page, presses Select All (Cmd+A, or Ctrl+A on Windows), then Copy (Cmd+C or Ctrl+C), and tells you "done".

You then run the engine's `clip` step. It reads their clipboard, hides anything that looks like a password, saves the text as `router-page.txt` and writes a first-pass `router.json`.

If they would rather paste the text into the chat, or send a screenshot, that works too: save pasted text to a file and run `clip --from <file>`, or read the screenshot and write `router.json` yourself.

## Where the device list is

| Router | Usual address | Where to click after logging in |
| --- | --- | --- |
| TP-Link Archer | 192.168.0.1 | **Clients**, on the first page (Network Map). Tested on an Archer C6. |
| TP-Link (older green pages) | 192.168.0.1 | DHCP → **DHCP Clients List**, or Wireless → **Wireless Statistics** |
| Jio (JioFiber, AirFiber) | 192.168.29.1 | **Network** → LAN clients, or the device list on the home page |
| Airtel | 192.168.1.1 | **Connected devices**, or Status → LAN / WLAN clients |
| BSNL, Syrotech, Netlink | 192.168.1.1 | Status → **User Device Information** or DHCP clients |
| D-Link | 192.168.0.1 | **Connected Clients** on the home page |
| Netgear | 192.168.1.1 | **Attached Devices** |
| Mesh systems (Deco, Nest, eero) | none | They have no web page. Ask for a screenshot of the device list in the phone app. |

Only the first row has been tested with this skill. For the others, tell the person the usual name and add "or whichever page lists the connected devices".

## Checking the first pass

`clip` is a rough reader. Open `router-page.txt` and `router.json` together and correct the JSON where it disagrees with the text.

- **Names.** The name should be the label shown next to that hardware address. Fix names it took from a column heading or left empty.
- **Online or not.** Routers often list devices that were connected earlier, greyed out, with dashes, or marked "offline". Those get `"online": false`.
- **Band.** Record it only if the text states it for that device ("2.4G", "5G", "Wired"). Many pages show the band as an icon that does not copy; leave it out then. Do not guess it from the name: a phone called "Nord-CE3-5G" is not necessarily on 5 GHz.
- **Speeds.** In a "Tx/Rx" pair, the first number is router to device; that is `txRate`.
- **Signal.** Only if shown in dBm. Many routers do not show it.
- **Router details.** If the copied text shows the model, firmware or the public (WAN / Internet) IP address, add them at the top level of `router.json`.

If the page also showed wireless settings and they were copied, you may fill in `bands` (channel, width, security, mode). Never copy a Wi-Fi password into any file, and do not read one out.

`references/data-format.md` lists every field.

## If you do have a browser tool

Some setups give you a tool that drives the person's own browser. You may use it to read the page instead of asking them to copy, but only in a tab they have logged in to themselves, and only to read. Never click Save, Apply, Reboot, Reset, Restore, firmware update, or Block / Blacklist next to a device, and stay off any WPS page. If a page asks to save changes when you leave it, discard them. Log out when you are done.

Always offer the copy route first. Most people do not have such a tool, and the skill must work the same for everyone.
