# Validation evidence and limits

Validation date: 2026-11-10. Credentials, organization identifiers and real private network details are intentionally excluded from this repository.

## Completed integration checks

| Check | Evidence |
| --- | --- |
| Windows native callback | Actual `com.cloudflare.warp://` dispatch delivered a synthetic JWT through the executable to authenticated localhost IPC |
| Association restoration | Compared HKCU registry state and effective Windows handler before and after dispatch |
| Failure handling | Automated timeout/restoration-failure tests verify cleanup and withholding of tokens |
| Existing WG import | Imported a matching registration and key, then queried live status and VNETs |
| Fresh WG registration | Go CLI created a throwaway registration and matched the returned public key |
| WireGuard connectivity | Isolated userspace netstack completed an authenticated peer handshake without installing OS routes |
| VNET switching | CLI selected a nondefault VNET, read back the expected UUID, and restored default |
| Device rename | PATCH followed by GET confirmed the display name |
| Deregistration | CLI DELETE succeeded for the throwaway registration and cleared its local credentials |
| MASQUE configuration | Created a separate P-256 registration and exported usque JSON |
| Original usque compatibility | Unmodified usque loaded the JSON; a local HTTP proxy trace request returned HTTP 200, `warp=on` and `gateway=on` |
| MASQUE with nondefault VNET | Selected a nondefault VNET, restarted usque, confirmed the public trace, and restored default |

These checks did not log into the original WARP app or activate a system-wide default route. Browser SSO output was also exercised independently of the native callback path. Initial browser login can time out when the browser has not dispatched the callback; that case restored the association correctly.

## Automated CLI coverage

Tests exercise bare interactive registration through configuration export, the shared input reader, selecting the correct device/token for VNET switching, direct selectors without menus, device tables with VNET names, cancellation and confirmation of deletion, explicit key display, export aliases, protocol mismatch rejection and grouped help. Existing app/auth/store tests cover lifecycle and recovery behavior. See [development instructions](DEVELOPMENT.md) for commands.

## Verification boundaries

A successful handshake or public HTTP trace does not prove private destination reachability, VNET isolation, private DNS, or policy behavior for a particular application. No specific private IP/hostname/port was supplied for this validation. Test these separately for each intended network.

Native dispatch confirms OS handler invocation; real browser choices may still require a confirmation button or explicit handler selection. Windows UserChoice and Firefox preferences can prevent automatic dispatch and require manual fallback. Linux/macOS currently use manual login rather than native handler takeover.

Same-device registration-token refresh/rotation, token lifetime, immediate termination of established sessions after deregistration, and long-term enrollment expiry have not been established. Separate registrations provide independent VNET state; simultaneous tunnel/proxy behavior also depends on the client and local routing configuration.
