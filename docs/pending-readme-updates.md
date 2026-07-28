# Pending README Updates

Notes on shipped features/fixes not yet folded into README.md/README_RU.md. Clear each entry out once its content has been merged into both READMEs during release prep.

## Ingestion token: real auto-generation + dashboard status/regenerate (v0.27.0, 2026-07-27)

The ingestion token that authenticates `POST` requests to `/api/v1/inventory` and `/api/v1/linux/inventory` is now genuinely auto-generated whenever `Install-Server.ps1` runs with no explicit `-Token` and no previously saved value - this was always the documented behavior but was never actually implemented before; a blank token used to mean ingestion ran completely unauthenticated. Settings > General's new "Ingestion Token" section shows whether a token is configured and lets an admin regenerate it - like the Admin Password page, the current value is never displayed on this Settings page, only shown once, immediately after a regenerate action, since that's the only moment it's known in plaintext (it remains viewable elsewhere, in plaintext, on the Client package tab's build-package field). Regenerating breaks ingestion for every already-installed client until each is reconfigured with the new value - and it does NOT rewrite an already-built GPO package, so any not-yet-deployed package still has the old token baked in and must be rebuilt from the Client package tab, not just redeployed.

The existing README text about the install wizard's 4-question fresh-install flow will also need a wording touch-up at release time: both `README.md` and `README_RU.md` (line ~125 in each) currently say the auto-generated token "isn't shown anywhere in the dashboard" - that's no longer true, it can now be checked/regenerated via Settings > General. Fix both files, not just the English one.

`README.md:602`'s guidance to "prefer a low-sensitivity ingestion token" for SYSVOL-deployed GPO packages is also worth revisiting at release time - it predates this plan, and since every install now auto-embeds the server's real token into `Install-ClientGpo.cmd`, the overall posture is better than before, but the wording itself hasn't been updated to reflect that.

## License file ACL restriction (v0.27.0, 2026-07-27)

`_licenses/licenses.json` is now restricted to Administrators+SYSTEM, matching the protection `server-config.json` already had.
