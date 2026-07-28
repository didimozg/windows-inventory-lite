# Pending README Updates

Notes on shipped features/fixes not yet folded into README.md/README_RU.md. Clear each entry out once its content has been merged into both READMEs during release prep.

## Ingestion token: real auto-generation + dashboard status/regenerate (v0.27.0, 2026-07-27)

The ingestion token that authenticates `POST` requests to `/api/v1/inventory` and `/api/v1/linux/inventory` is now genuinely auto-generated whenever `Install-Server.ps1` runs with no explicit `-Token` and no previously saved value - this was always the documented behavior but was never actually implemented before; a blank token used to mean ingestion ran completely unauthenticated. Settings > General's new "Ingestion Token" section shows whether a token is configured and lets an admin regenerate it - like the Admin Password page, the current value is never displayed anywhere, only shown once, immediately after a regenerate action, since that's the only moment it's known in plaintext. Regenerating breaks ingestion for every already-installed client until each is reinstalled or reconfigured with the new value.

The existing README text about the install wizard's 4-question fresh-install flow will also need a wording touch-up at release time: it currently says the auto-generated token "isn't shown anywhere in the dashboard" - that's no longer true, it can now be checked/regenerated via Settings > General.

## License file ACL restriction (v0.27.0, 2026-07-27)

`_licenses/licenses.json` is now restricted to Administrators+SYSTEM, matching the protection `server-config.json` already had.
