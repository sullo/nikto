# Design: DEBUG HTTP verb false-positive fix

## Problem

In `nikto_options.plugin`, the DEBUG check compares the DEBUG response MD5 to `$junkmethodresp`, but that baseline is only set when the junk verb returns 200.

When the junk verb is rejected (405/501/400 — the common case), `$junkmethodresp` stays `undef`. Then:

```perl
$res == 200 && (LW2::md5($content) ne $junkmethodresp)
```

is true for any DEBUG 200, because an MD5 never equals `undef`. Hosts that merely answer 200 to `DEBUG /` (often with the home page) are reported as:

> DEBUG HTTP verb may show server debugging information

with no evidence that DEBUG is implemented or that ASP.NET debugging is enabled.

## Goals

1. Distinguish “junk rejected / DEBUG 200” from “junk 200 / DEBUG 200 with different body”.
2. Only report when the response matches the IIS/ASP.NET DEBUG protocol (`Command: stop-debug`), not merely “differs from baseline”.
3. Keep the change local to `nikto_options.plugin`; no CLI, config, CSV, or parser changes.

## Non-goals

- Changing the junk-method false-positive finding (`999967`) beyond continuing to report it only when junk returns 200.
- Changing OPTIONS / PROPFIND / TRACE / TRACK behavior.
- Rewording finding `999972` (optional follow-up).

## Approach

Full parity with the Go port fix: **baseline present + status-or-body difference + protocol marker**.

### 1. Junk baseline (status + MD5)

After the existing junk-verb `nfetch`:

- If the probe **completed** (HTTP status code present / non-empty `$res`), always record:
  - `$junk_status` = `$res`
  - `$junk_md5` = `LW2::md5($content)`
- Still emit finding `999967` only when `$res == 200` (unchanged).
- If the probe **did not complete** (no usable status — transport/`whisker` failure, empty `$res`), do **not** set baseline and **skip** the DEBUG check entirely.

### 2. DEBUG probe

When baseline is present and `$mark->{'terminate'}` is clear:

- `nfetch` `DEBUG` `/` with headers:
  - `Command` => `stop-debug`
  - `Content-Length` => `0`
- Use the same header hashref pattern already used for PROPFIND in this plugin.

### 3. Finding criteria

Report `999972` only when **all** of:

1. Baseline is present (`$junk_status` / `$junk_md5` set).
2. DEBUG status differs from `$junk_status` **or** `LW2::md5($content)` differs from `$junk_md5`.
3. Body matches the protocol reply (after optional surrounding whitespace):

   - `^\s*OK\s*$`, or
   - `Error Code\s*=\s*0x[0-9A-Fa-f]+`

A 200 whose body is the home page (or any non-protocol content) is **not** a finding.

Finding id, URI, method, and current message text remain as today unless changed in a follow-up.

## Error / terminate handling

- Existing `return if $mark->{'terminate'}` before DEBUG stays.
- No new interactive or failure-limit behavior.

## Testing (manual)

| Case | Expected |
|------|----------|
| Junk 501, DEBUG 200 + home page | No `999972` |
| Junk 200 (same page), DEBUG 200 + same page | No `999972` (and `999967` as today) |
| Junk non-200, DEBUG 200 + body `OK` | Report `999972` |
| Junk probe fails (no status) | Skip DEBUG; no `999972` |
| DEBUG 200 + `Error Code = 0x00000000`-style body + baseline differ | Report `999972` |

## Files

- `program/plugins/nikto_options.plugin` — only file to change
