# wgcfzt

An independent Go CLI for Cloudflare Zero Trust device registration, per-device virtual network (VNET) selection, and WireGuard or [usque](https://github.com/Diniboy1123/usque) configuration export.

Module: `github.com/pccr10001/wgcfzt`. MIT licensed. This is an independent implementation, not an official Cloudflare client. It uses WARP client APIs that may change.

The CLI manages multiple registrations without starting the official WARP app, installing a TUN adapter, or changing OS routes. Use a WireGuard client or usque to establish the tunnel. Organization enrollment and access policies still apply.

## Install

Requires Go 1.26 or later:

```sh
go install github.com/pccr10001/wgcfzt@latest
```

Or build from source:

```sh
git clone https://github.com/pccr10001/wgcfzt.git
cd wgcfzt
go build -o wgcfzt .
```

On Windows, build with `go build -o wgcfzt.exe .` and invoke `./wgcfzt.exe` if the current directory is not on PATH.

## Interactive registration

```sh
wgcfzt reg
```

Enter the organization slug (for example `example-team`), a local device name, the tunnel protocol, and the display name. Review and accept Cloudflare's terms. Enter accepts a displayed default; `q` cancels a menu.

On Windows, the CLI temporarily registers itself for `com.cloudflare.warp://`, opens Firefox at the organization's `/warp` page, and waits for SSO. Complete the login and approve the browser's callback prompt. The short-lived callback process sends the token to the waiting parent over authenticated localhost IPC and exits automatically. The parent restores the original protocol association **before** using the token to register a device, then lets you choose its VNET and writes its configuration. No additional callback window input is required.

The private key is generated locally. Login JWTs and registration bearer tokens are never printed during normal operations; the login JWT is not retained for future logins.

For a fully specified registration:

```sh
wgcfzt reg --team example-team --device labs-wg --protocol wireguard --name workstation --vnet labs --accept-tos
wgcfzt reg --team example-team --device labs-masque --protocol masque --vnet labs --accept-tos
```

These commands skip the setup questions but still require browser SSO. `--accept-tos` accepts https://www.cloudflare.com/application/terms/ . Use only the organization slug for `--team`, not a URL.

## Device management

```sh
wgcfzt devices
wgcfzt devices list --offline
wgcfzt status
wgcfzt status --device labs-wg
wgcfzt device show --device labs-wg
wgcfzt device rename "New display name" --device labs-wg
wgcfzt device dereg
wgcfzt device dereg --device labs-wg --yes --non-interactive
```

`device` and `devices` are aliases. The table lists locally managed profiles, protocol, registration state, and selected VNET. By default it queries each ready device; failed queries are explicitly marked and use cached VNET information. `--offline` uses only cached state. It does not enumerate devices belonging to other users or profiles absent from this computer.

Operations on a single device prompt for a selection when `--device` is omitted. `--device` accepts a local profile name or an exact saved registration ID; `--profile` remains a compatibility selector. Deletion prompts for the local name unless `--yes` is supplied. Remote deletion must succeed before local credentials and the default exports are cleared. External export copies are not removed. A local tombstone remains to record deregistration.

## VNET selection

```sh
wgcfzt vnet
wgcfzt vnet --device labs-wg
wgcfzt vnet --device labs-wg --vnet labs --non-interactive
wgcfzt vnet list --device labs-wg
wgcfzt vnet use labs --device labs-wg
```

Bare `vnet` selects a device, then a network. A selector can be a network name or UUID. Ambiguous names are rejected. The CLI PATCHes the selection and reads it back to verify the UUID.

VNET selection is server-side state associated with one registration. **Reconnect WireGuard or restart usque after switching.** The API does not reconnect your client. Copies of the same registration share its VNET choice. To use different VNETs concurrently, create separate registrations with independent keys and select a VNET for each. Your client must also support the required simultaneous tunnels or proxies.

The CLI does not enumerate private route inventory or automatically implement the official client's split-tunnel/DNS policy. Local routing decides which traffic enters a tunnel; Cloudflare uses the selected VNET, routes, and policies to forward that traffic. See [API and routing details](docs/API.md).

## Configuration commands

```sh
wgcfzt config export --device labs-wg -o labs.conf
wgcfzt config export --device labs-wg --vnet labs -o labs.conf
wgcfzt config usque --device labs-masque -o usque.json
wgcfzt config showkey --device labs-wg
wgcfzt config showkey --device labs-masque
```

`config export` produces WireGuard configuration. `config usque` produces usque JSON from a MASQUE registration. `generate` remains available and chooses the saved protocol automatically; `--format wireguard|usque` explicitly selects an export format. `--vnet` on an export selects and verifies that VNET first. `--offline` skips refresh, but an explicit `--vnet` still requires the API.

WireGuard options: `--mtu 1280`, `--keepalive 25` (0 disables), `--dns 1.1.1.1`, and `--allowed-ips 10.0.0.0/8`. AllowedIPs defaults to `0.0.0.0/0,::/0`; DNS is omitted by default. Choose routes and DNS appropriate for your environment before activating the configuration.

`config showkey` deliberately prints the private key to stdout. For WireGuard it is the Base64 raw Curve25519 key; for MASQUE it is Base64 SEC1 P-256 DER. Treat terminal output and exported configurations as credentials. A WireGuard key cannot be converted to a P-256 MASQUE key; create a separate MASQUE device.

To use an existing usque installation:

```sh
wgcfzt config usque --device labs-masque -o usque.json
usque --config usque.json http-proxy --bind 127.0.0.1
```

Check `usque --help` and `usque http-proxy --help` for the installed version's bind/authentication options. VNET selection is performed by wgcfzt against that same registration, not by embedding a VNET field in usque JSON. After changing it, restart usque using the existing JSON (or export again if registration details changed).

## Login fallback and recovery

Automatic native callbacks are supported on Windows. Linux/macOS use manual input. Windows UserChoice and explicit Firefox handlers are respected; if they prevent safe temporary takeover, the CLI falls back to manual login.

```sh
wgcfzt reg --manual
wgcfzt reg --team example-team --device labs-wg --jwt-file /secure/path/token.txt --accept-tos
```

Manual login shows `view-source:https://example-team.cloudflareaccess.com/warp` so you can copy the JWT or full callback URL without opening the original WARP app. Do not approve opening the original app. `--browser default` selects the system browser instead of Firefox. `--jwt-file -` reads stdin; avoid putting tokens directly in shell command arguments. A fully specified unattended command can use `--non-interactive` and `--jwt-file`.

Timeout and Ctrl+C restore the original Windows association. After force-kill, power loss, or failed restoration, recover with the same config directory:

```sh
wgcfzt recover
wgcfzt --config-dir /custom/path recover
```

A pending backup blocks every new registration, including JWT-file registration, until recovery finishes. External handler changes are detected rather than overwritten. `--timeout` defaults to five minutes. Browser confirmation may still be required on every invocation.

An interrupted registration retains its key and any returned device ID/token. Resume explicitly:

```sh
wgcfzt reg --device labs-wg --team example-team --resume --accept-tos
```

Registration POSTs are not automatically retried because an uncertain response could otherwise create duplicate remote devices. No same-device registration-token refresh/rotation flow has been verified; switching VNET does not refresh the token. If authorization becomes invalid, diagnose enrollment/session/policy failures and create a new device registration when needed.

## Import an existing WireGuard registration

```sh
wgcfzt import --device imported --team example-team --registration registration.json --key-file wireguard-key.json
```

The registration JSON must include its ID, account ID, bearer token, tunnel type, public key, and configuration. The key file can contain a raw Base64 private key or JSON with `private_key`. Public/private keys must match. Import refuses to overwrite an existing profile.

## Storage and automation

Defaults:

- Windows: `%LOCALAPPDATA%\wgcfzt`.
- Linux/macOS: `~/.config/wgcfzt`; `XDG_CONFIG_HOME` is honored.
- Override with `--config-dir` on any command.

Each profile is stored under `profiles/<name>/account.json`, with exports alongside it (`wg-profile.conf` or `usque.json`). Files contain secrets and are protected with per-user Windows ACLs or Unix directory/file modes 0700/0600. Use separate local names for independent devices; copying a profile does not create another remote device.

Use `--device` and operation flags to skip selection, `--yes` to confirm deletion, and `--non-interactive` to reject missing selections instead of prompting. New registrations with `--non-interactive` require `--jwt-file`; browser authentication remains available for fully specified commands without that flag. Errors return a nonzero exit status.

Run `wgcfzt --help` for grouped commands, and `<command> --help` for flags.

## Documentation and verification

- [API workflow, credentials, VNET and routing](docs/API.md)
- [Development, callback lifecycle and tests](docs/DEVELOPMENT.md)
- [Validation evidence and limits](docs/VALIDATION.md)

The implementation has been tested with real WireGuard handshakes and an unmodified usque client. Private destination routing and private DNS require environment-specific verification; public trace success alone does not prove private VNET access.
