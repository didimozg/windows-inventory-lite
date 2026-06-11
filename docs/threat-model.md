# Threat Model

## Assets

- Client inventory reports with host names, OS data, Office data, installed software, and activation facts.
- Server report store under `ProgramData`.
- Saved WinRM client action logs under the server `DataPath`.
- Windows Service identities on client and server hosts.
- Optional shared token used by clients in `X-Inventory-Token`.
- Optional Basic Auth credentials and WinRM credentials entered by an operator.

## Trust Boundaries

- Client host to server HTTP listener.
- Server HTTP listener to local report storage.
- Browser user to dashboard.
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
