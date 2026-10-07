## Attack path

Establish the attack path from the code before building anything, citing path, symbol and line for each part:

- the attacker and the least privilege they need (unauthenticated, a named role, or an administrator);
- the source, meaning the exact entry point the attacker controls (route and parameter, form field, upload, API field or header);
- each step that carries the value to the sink (storage, transformation, missing check);
- the sink and whose context it executes in (another user's browser, the server, a background job);
- and the trust boundary it crosses.

When only an actor who already holds the impacted capability can reach the source, for example an administrator storing script in content only administrators can edit when administrators may already add script, it is not a vulnerability: record hardening or not a finding and say why.

A reproduction must travel that path. Deliver the payload only through the source, signed in as the least-privileged attacker role, and observe the effect through the sink as the victim. Setup may create that attacker account and the baseline pages, blocks, forms or permissions the scenario needs, but never the payload: do not write the malicious value into the database, files, caches or configuration directly, and do not plant it with an account more privileged than the attacker's. Report reproduction as reproduced only when the payload entered through the source and was observed at the sink; a shortcut is not_reproduced, with the reason.

report.md states the attacker, source, path, sink and boundary, and evidence items carry a role of source, propagation, sink or boundary.
