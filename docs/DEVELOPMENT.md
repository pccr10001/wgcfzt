# Development and recovery design

## Layout

| Path | Responsibility |
| --- | --- |
| `main.go` | Signal cancellation and process exit |
| `internal/cli` | Cobra commands, shared interactive reader, device/VNET selection |
| `internal/auth` | JWT validation, authenticated loopback IPC, Windows protocol restoration |
| `internal/api` | WARP HTTP transport, DTOs and redacted errors |
| `internal/store` | Named profile storage, atomic writes, permissions and locks |
| `internal/app` | Registration lifecycle, key generation, VNET verification and exports |

Module: `github.com/pccr10001/wgcfzt`. Cobra handles commands; `golang.org/x/sys` provides OS registry, permissions and synchronization primitives. Go's standard library provides HTTP and cryptography.

## Interactive command behavior

`reg` prompts for missing setup when the organization or device selector is absent. It then reuses the same buffered reader for manual login and VNET selection. Replacing the reader with a new buffer over a limited stream can consume input intended for a later prompt; tests guard reader preservation.

Single-device operations use an explicit local name/ID or prompt from eligible locally stored devices. Deregistered profiles are excluded from selection. `--non-interactive` rejects a missing device selector; deletion additionally requires `--yes`. EOF and cancellation return errors rather than looping. `devices` is a table; its subcommands perform management actions. `device` is its alias.

Root help groups registration, device/network management, and configuration commands. `generate` remains compatible; `config` is a command group, not an alias for generation. Only `config showkey` deliberately prints a private key.

## Callback lifecycle

The parent snapshots the current-user `HKCU\Software\Classes\com.cloudflare.warp` tree, installs a temporary command pointing to the same executable, and verifies the effective association with Windows. HKLM and protected UserChoice are not modified. Explicit Firefox handler preferences trigger a manual fallback. A per-user Global named mutex prevents concurrent association ownership across configuration directories.

The handler command includes `callback -- "%1"`; the separator prevents URL content from becoming CLI flags. Session data contains a loopback URL, random nonce and team slug, not a saved JWT. The helper validates the token and posts to the exact loopback URL with the nonce. Its HTTP transport uses no proxy and follows no redirects. On HTTP 204 it returns and the process exits, while the parent continues.

`auth.Login` restores the association before returning the JWT. Restoration failure withholds the JWT from the registration layer. Timeout, cancellation and ordinary completion all restore. Force-kill cannot execute deferred cleanup; a protected backup enables `recover`, and any pending backup blocks subsequent registrations.

Restoration compares ownership before changing values, restores the tree in place, and records a checkpoint for interrupted restoration. External handler changes are reported instead of overwritten. Existing keys retain their ACLs where possible. Backups are removed only after successful restoration.

Native dispatch passes the callback in a process argument, so it may be visible to local process inspection. The CLI does not log it. For environments avoiding that exposure, use `--jwt-file` with a protected file or stdin. Never include real keys or tokens in tests or documentation.

## Registration states

```text
pending -> registered -> ready -> deregistered
                         ^
          MASQUE enrollment (MASQUE profiles only)
```

A pending profile saves the private key before POST. Returned device IDs and tokens are persisted before later operations. POST is not automatically retried. `reg --resume` is explicit and does not issue a second POST once a device ID is saved. Failed VNET selection retains the usable registration for a later retry. Exports validate that the remote public key matches the local private key.

Deregistration clears local secrets only after remote success. A disk-write failure after remote deletion is reported and must be handled; do not treat this as an intact registration. Account files and default exports contain secrets: protect backups and external copies as carefully as the originals.

## Automated verification

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

Tests cover mocked registration, MASQUE enrollment, VNET readback, device deletion, key encodings, export validation, redacted failures, interactive registration, multi-device selection, noninteractive operations, explicit private-key display, grouped help, callback delivery/restoration ordering, recovery errors, storage validation and writer locks.

Routine Windows tests use isolated registry keys. The opt-in test below invokes actual native URL dispatch with a synthetic JWT and then compares the restored association. It does not register with Cloudflare or activate a tunnel:

```powershell
go build -o dist\wgcfzt.exe .
$env:WGCFZT_PROTOCOL_TEST_EXE = (Resolve-Path .\dist\wgcfzt.exe).Path
$env:WGCFZT_PROTOCOL_TEST_DIR = "$env:LOCALAPPDATA\wgcfzt-callback-test"
go test ./internal/auth -run TestWindowsNativeCallbackRoundtrip -v
Remove-Item Env:WGCFZT_PROTOCOL_TEST_EXE
Remove-Item Env:WGCFZT_PROTOCOL_TEST_DIR
```

If restoration fails, retain the test directory and run `recover` using that directory before another login. Never delete a pending backup to suppress recovery checks.

## Cross-platform builds

```sh
GOOS=linux GOARCH=amd64 go build -o dist/wgcfzt-linux-amd64 .
GOOS=darwin GOARCH=arm64 go build -o dist/wgcfzt-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o dist/wgcfzt.exe .
```

In PowerShell use `$env:GOOS` and `$env:GOARCH`, then remove them after building. CI runs tests with race detection, vet and builds on Linux, Windows and macOS. It uses mock APIs, not organization credentials or real callback associations.
