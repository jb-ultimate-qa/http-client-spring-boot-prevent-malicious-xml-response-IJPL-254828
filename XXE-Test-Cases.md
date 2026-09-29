# IJPL-254828 — XXE in the HTTP Client's DOMParser — Test Plan

> ⚠️ **Source note:** The YouTrack ticket `IJPL-254828` is private/auth-gated and the
> YouTrack MCP was not reachable from the agent session, so this plan is derived from the
> **issue title / standard XXE semantics**, not the ticket body. Cross-check the summary
> and expected fix behavior against the real ticket before signing off.

## Short summary

The IntelliJ **HTTP Client** exposes a `DOMParser` in `.http` response-handler scripts
(`new DOMParser().parseFromString(response.body, "application/xml")`). Before the fix, this
parser processed inline DTDs and resolved **external entities**. A malicious (or compromised)
server can therefore return XML that, when parsed by an `.http` response handler, makes the
IDE:

- **read local files** off the developer's machine (classic file-read XXE),
- **make out-of-band / SSRF requests** to attacker-chosen URLs (external DTD/parameter entity),
- **blow up on entity expansion** (billion-laughs DoS).

**Fix expectation:** the DOMParser must disable DTD processing / external-entity resolution
(and entity expansion), while still parsing legitimate XML correctly.

## Setup

1. Open the `demo40` project, run **`Demo40Application`** (Spring Boot, `http://localhost:8080`).
   - On startup it logs `[XXE-TEST] Canary file written to: <path>` — this canary file is the
     file-read target. It contains only the marker `SECRET_CANARY_VALUE_DO_NOT_LEAK`.
2. Open **`xxe-tests.http`** and run each request with the **response-handler** gutter action.
3. Read results in the HTTP Client **Response Handler / Tests** tab.

The Spring app acts as the *malicious server*; the IDE's HTTP Client DOMParser is the component
under test. Everything stays on `localhost`, so nothing leaves the machine.

## Test cases

| # | Name | Endpoint | Payload type | VULNERABLE result | FIXED result (pass) |
|---|------|----------|--------------|-------------------|---------------------|
| TC1 | File-read XXE | `/xxe/file-entity` | External **general** entity `SYSTEM "file://…canary"` | Parsed `<value>` contains `SECRET_CANARY…` | `<value>` empty / entity unresolved / parse error — **no canary** |
| TC2 | OOB / SSRF | `/xxe/external-dtd` | External **parameter** entity → `http://localhost:8080/xxe/collect` | `/xxe/oob-hits` > 0 (server logged an OOB hit) | `/xxe/oob-hits` == `0` |
| TC3 | Entity expansion (DoS) | `/xxe/billion-laughs` | Nested internal entities (depth 4) | Expanded text large / parse slow | Expansion disabled — short/empty text, fast |
| TC4 | Benign control | `/xxe/benign` | Plain XML, no DTD | `<value>` == `hello-world` | Same — **must still pass** (no false positive / regression) |

### TC1 — File-read XXE (primary signal)
- **Steps:** run TC1 with response handler.
- **Pass:** test "no local file leaked via XXE" passes; log shows `<value>` without the canary.
- **Fail (vuln):** log shows the canary string → local file contents were injected into the DOM.

### TC2 — Out-of-band / SSRF
- **Steps:** run **TC2**, then run **TC2-check**.
- **Pass:** `oob-hits` == `0`; no `[XXE-TEST] !!! OOB/SSRF hit` line in the app console.
- **Fail (vuln):** `oob-hits` ≥ 1 and the app console logs an OOB hit → parser fetched external DTD.

### TC3 — Entity expansion / billion-laughs
- **Steps:** run TC3.
- **Pass:** expanded length small, parse fast; test passes.
- **Fail (vuln):** large expanded length (and noticeable delay). *Depth is intentionally small
  so a vulnerable IDE degrades but does not freeze.*

### TC4 — Benign control (regression guard)
- **Steps:** run TC4.
- **Pass:** `<value>` == `hello-world`. Confirms the fix did not break normal XML parsing.

## Sign-off checklist

- [ ] Verified summary/behavior against the real IJPL-254828 ticket.
- [ ] TC1 passes (no file read).
- [ ] TC2 passes (no OOB request).
- [ ] TC3 passes (no entity expansion).
- [ ] TC4 passes (benign XML still parses).
- [ ] Re-ran TC1–TC3 on an **old/unfixed** IDE build and confirmed they **fail** there
      (proves the tests actually detect the vulnerability, not just a passing IDE).

## Notes / caveats

- Confirm `DOMParser` is the exact API named in the ticket and that the fix targets the HTTP
  Client's script environment (not, say, XML tooling elsewhere in the IDE). Adjust endpoints if
  the ticket describes a different entry point (e.g. auto-parsing of XML response bodies).
- If the HTTP Client sandbox blocks `new DOMParser()` outright after the fix, that is also a
  valid "not vulnerable" outcome — note it during sign-off.
