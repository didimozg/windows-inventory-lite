# Threat Model

## Assets

- Client inventory reports with host names, OS data, Office data, installed software, and activation facts.
- Server report store under `ProgramData`.
- Saved WinRM client action logs under the server `DataPath`.
- Windows Service identities on client and server hosts.
- Optional shared token used by clients in `X-Inventory-Token`.
- Optional Basic Auth credentials and WinRM credentials entered by an operator.
- The TLS server certificate and its private key in the `LocalMachine\My` certificate store.
- The license inventory catalog (`licenses.json`) with admin-entered Name, Version, License, and Comment fields.
- The certificate history log (`_certificates/certificate-history.json`) recording every uploaded certificate and the risks found at upload time.
- Cached Active Directory computer descriptions (adDescription field on each report), and AD credentials when explicit AD credentials (rather than the service identity) are configured.

## Trust Boundaries

- Client host to server HTTP/HTTPS listener.
- Server HTTP/HTTPS listener to local report storage.
- Browser user to dashboard.
- Browser user to the `LocalMachine\My` certificate store, via the certificate upload endpoint.
- Installer scripts to Windows Service Control Manager and firewall configuration.
- Server-side WinRM action runner to remote client hosts.
- Server-side WinRM action runner to local TrustedHosts configuration.

## Attacker-Controlled Inputs

- HTTP request body sent to `POST /api/v1/inventory`.
- HTTP headers, including missing or invalid `X-Inventory-Token`.
- Computer names and software names inside submitted JSON.
- Local command-line parameters passed during installation.
- Dashboard requests that start client install, update, or uninstall jobs.
- POST body to `POST /api/v1/client-package/configure` (serverUrl, token, intervalHours fields) that rewrites `Install-ClientGpo.cmd` on the server.
- WinRM target names, IP addresses, ranges, usernames, and passwords entered by an operator.
- POST body to `POST /api/v1/server/certificate` (base64 PFX bytes, PFX password) that imports a certificate into `LocalMachine\My` and records it as the configured certificate, without changing whether HTTPS is in use.
- `DELETE /api/v1/server/certificate`, which removes the configured certificate from `LocalMachine\My` and turns HTTPS off if it was using that certificate. No request body; the only input is the authenticated request itself.
- POST body to `POST /api/v1/server/settings` (staleHours, useHttps, port, enableHttp, httpsPort, acknowledgeRisks fields) that changes the stale threshold and independently starts, stops, or moves the HTTP and HTTPS listeners using the currently configured certificate.
- POST/PUT bodies to `/api/v1/licenses` (name, version, license, comment, computers fields) written to `licenses.json` and rendered back into the dashboard.
- POST body to `POST /api/v1/server/admin-password` (newUsername, currentPassword, newPassword) that sets up or rotates the dashboard's Basic Auth username and password. `currentPassword` is required only when Basic Auth is already configured.
- The computer name embedded in a client's inventory report, when AD sync is enabled: used to build an LDAP search filter (see AdLookupService.LookupComputerDescription), escaped per RFC 4515 before use.

## Required Invariants

- Clients must not export product keys, credentials, or user documents.
- Server must store reports as data files and must not execute report content.
- Dashboard must treat report fields as untrusted display data.
- Operators must restrict server exposure with firewall rules, listener scope, token checks, or a reverse proxy.
- Service install scripts must not delete unrelated files or modify unrelated services.
- WinRM client actions must be available only to trusted administrators.
- Saved client action logs must not contain passwords.
- TrustedHosts changes must be explicit and limited to requested targets.
- The client package configure endpoint must validate all fields before writing `Install-ClientGpo.cmd` and must be protected by the same access controls as the rest of the dashboard.
- The certificate endpoints must require the same Basic Auth as the rest of the dashboard, must reject oversized or malformed PFX input before touching the certificate store, and must never write the PFX password to logs or saved config.
- Enabling HTTPS from `POST /api/v1/server/settings` must re-evaluate the configured certificate's risks on every call and must not switch over silently when risks are present; it must require an explicit `acknowledgeRisks` flag in that case.
- License records are untrusted display data. The dashboard must escape them the same way it escapes report fields.
- The admin password endpoint must require the current password to change an already-configured password. It may accept a new username and password without a current password only while Basic Auth is not yet configured — at that point the endpoint is no less exposed than the rest of the dashboard, which is already unauthenticated.
- TLS connections must use an explicit protocol version (not "negotiate any"), since at least one .NET Framework runtime treats the auto-negotiate value as "no protocols enabled" and rejects the handshake outright.
- Every accepted socket must have a read/write timeout, so a stalled handshake or a client that opens a connection without sending data cannot hold a server thread indefinitely.
- `POST /api/v1/server/settings` must reject a request that disables HTTP unless HTTPS is genuinely active (a live listener with a usable certificate) in that same evaluation, so the settings endpoint itself can never leave the server with no reachable listener.
- Port changes for either listener must bind and start the new listener before touching the old one, so a failed rebind (port in use, no permission) leaves the previously working listener running unaffected.
- The LDAP filter built from a client-reported computer name must have its special characters escaped before use, to prevent LDAP injection from a maliciously-named reporting host.
- An unreachable or slow AD must not block or fail inventory report ingestion.

## Main Risks

- Unauthorized report submission can poison inventory data.
- Unrestricted dashboard access can expose asset and software inventory.
- Plain HTTP can expose reports on untrusted networks.
- A broad listener prefix such as `http://+:8080/` can expose the service on more interfaces than intended.
- A compromised dashboard account can trigger remote client installation or removal through WinRM.
- Passing WinRM credentials through plain HTTP can expose administrative credentials.
- Broad TrustedHosts entries can weaken WinRM server authentication.
- Saved action logs can expose hostnames, usernames, and command output.
- A large `Content-Length` header or a slow-loris HTTP connection can exhaust server memory (mitigated in v0.1.0 with a 16 MB body limit and a 64 KB header limit).
- An operator or attacker with dashboard credentials can use `POST /api/v1/client-package/configure` to redirect the server URL in `Install-ClientGpo.cmd` to a different host. Clients that download and apply the updated package will send reports to the new address. Protect the dashboard with Basic Auth and limit access to the management network.
- Storing dashboard credentials in the Windows Service `ImagePath` registry key exposes them to any local user with registry read access (mitigated in v0.1.0: credentials are read from the config file, not the service command line).
- Unhandled server exceptions that return internal error details to the HTTP client can expose file paths or internal state (mitigated in v0.1.0: generic 500 response, details go to Windows Event Log).
- The first certificate upload happens over whatever transport is active. If the server is still plain HTTP, the PFX password crosses the network in cleartext for that one request. Documented as an operational risk; mitigate by performing the first upload from a trusted network or the server console.
- A compromised dashboard account can import an attacker-controlled certificate into `LocalMachine\My` and, on a follow-up call to `/api/v1/server/settings`, enable HTTPS with it, allowing on-path interception of subsequent traffic that trusts that certificate's issuer. Separating upload from enable does not remove this risk from an already-compromised account, but it does prevent an upload alone (e.g. a mistaken or malicious PFX submitted before the operator is ready) from silently flipping the listener.
- An operator can knowingly enable HTTPS with a risky certificate (expired, no SAN, weak key) by acknowledging the risk prompt. This is by design — it unblocks legitimate lab/test use — but it also means the risk check is not a hard control against a compromised or careless admin account.
- A compromised dashboard account can call `DELETE /api/v1/server/certificate` to remove the active certificate and force the server back to plain HTTP, a downgrade attack against anyone who connects afterward. This is the same class of risk as an account being able to enable HTTPS with an attacker's certificate in the first place - both require dashboard-level compromise, which Basic Auth and network restrictions are the actual controls against, not anything in the certificate endpoints themselves.
- License records accept arbitrary free text in the License and Comment fields. They are rendered into the dashboard as escaped text, not executed, but should not be treated as a place to store secrets.
- If a browser has cached Basic Auth credentials for the dashboard's origin, a malicious page could trigger a same-origin request the browser auto-authenticates (a CSRF-like risk inherent to Basic Auth, not specific to this project). The admin password change endpoint's current-password requirement limits the blast radius of this for that one action; other state-changing endpoints do not have an equivalent second factor.
- While Basic Auth is unconfigured, anyone who can reach the dashboard can set the initial username and password themselves, effectively claiming the account. This is an accepted tradeoff (see Required Invariants) rather than an oversight: the rest of the dashboard is equally open in that state. The mitigation is operational — configure Basic Auth immediately after install, before exposing the server beyond a trusted network.
- The HTTP-disable safety gate only evaluates listener state at the moment of the request. An operator can disable HTTP while HTTPS is genuinely working, then have HTTPS later stop working on its own (certificate expiry, deletion from the store by another tool or admin, a private key that no longer matches) with nothing left to re-evaluate the gate. The dashboard becomes unreachable until an administrator with local server access edits `server-config.json` to set `EnableHttp` back to `true` and restarts the service — documented as the recovery procedure in the README. This is an accepted operational risk of the safety gate's design, not a bug in it: the gate protects against the dashboard locking itself out at the moment of the change, not against a certificate degrading afterward.
- If explicit AD credentials are configured (rather than the service account identity), the password is encrypted at rest with Windows DPAPI (machine scope) before being written to server-config.json, unlike WebPassword/Token, which remain plaintext-plus-ACL. DPAPI at machine scope is decryptable by any sufficiently privileged process on the same host - it raises the bar over plaintext (protects against the config file being copied off the box or into a backup) but is not a substitute for restricting who can reach the server itself.
- AD sync is opt-in and off by default, so this entire risk surface does not apply to deployments that don't enable it.

## Controls

- Use `-Token` on server and client installation.
- Prefer a host-specific listener prefix or firewall scope for production.
- Use HTTPS termination or a reverse proxy outside trusted LAN segments.
- Keep the server `DataPath` writable only by the server service identity and administrators.
- Restrict read access to `C:\ProgramData\WindowsInventoryLite\server-config.json` to the service account and administrators. The file contains `Token`, `WebUsername`, and `WebPassword` in plaintext.
- Review generated JSON before sharing it outside the organization.
- Protect the dashboard with Basic Auth and network restrictions before enabling WinRM client actions.
- Prefer DNS computer names and Kerberos for WinRM. Use IP targets with TrustedHosts only on a trusted management network.
- Run the server service under the least-privileged domain or managed service account that can administer the intended client scope.
- Keep WinRM action log retention short enough for the environment and protect the log directory with server-side ACLs.
- Enable Basic Auth before using the `Client package` configure endpoint in any environment where unauthorized access is possible. The endpoint writes to the server filesystem and changes the deployment target URL for GPO clients.
- Configure Basic Auth immediately after install, from the dashboard `Change admin password` page or `-WebUsername`/`-WebPassword` at install time, before exposing the server beyond a trusted network — the initial setup step itself is intentionally unauthenticated (see Main Risks).
- Enable Basic Auth before exposing the `Certificate` or `General` tabs in any environment where unauthorized access is possible; together they can import a certificate into the machine store and switch the listener to HTTPS.
- Perform the first PFX upload from a trusted network or the server console, since it may travel over plain HTTP.
- Run the server service under an account with rights to write to `LocalMachine\My` if certificate management from the dashboard is required; `LocalSystem` already has this by default.
- Use the Settings `Change admin password` page to rotate `WebPassword` instead of editing `server-config.json` directly; rotating an existing password still requires the current one and updates the ACL-protected config file in place.
- Review the certificate history log on the `Certificate` tab periodically; an unexpected entry is a signal that a dashboard account may be compromised.
- Do not treat an acknowledged certificate risk warning as resolved — replace the flagged certificate with a valid one as soon as practical.
- Do not disable HTTP until HTTPS has been verified reachable from an actual client, not just accepted by the settings endpoint. Keep local server access (RDP, console) available for the recovery procedure in case a certificate degrades after HTTP is off.
- Monitor certificate expiry independently of this application if HTTP is disabled in production; there is no built-in alerting for an approaching expiry date.
- Prefer the service account identity over explicit AD credentials when the service already runs under a domain account (which WinRM client actions already require) - it needs no additional secret in server-config.json.
