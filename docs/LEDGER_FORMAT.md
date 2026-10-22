# Ledger format

This is everything you need to verify a case's `ledger.jsonl` **without this tool**, for example as a bank, a regulator or opposing counsel checking a case file. Standard command-line tools are enough. `tests/test_known_answers.py` checks the tool against the worked example below, using values computed with `sha256sum` and OpenSSL, not with the tool.

## Entries

`ledger.jsonl` holds one JSON object per line (UTF-8). Each entry has:

| Field | Meaning |
|---|---|
| `seq` | 1, 2, 3, … with no gaps |
| `ts` | UTC time, ISO 8601, e.g. `2026-10-22T00:00:00+00:00` |
| `kind` | `case.create`, `event.add`, `event.update`, `artifact.link` or `artifact.record` |
| `payload` | the content (object) |
| `prev` | `hash` of the previous entry; 64 zeros for entry 1 |
| `actor` | optional; who wrote it |
| `kid` | optional; signing key id (present on signed entries) |
| `hash` | see below |
| `sig` | optional; Ed25519 signature, 128 hex characters |

Any other field means the ledger has been tampered with.

## Entry hash

1. Take `seq`, `ts`, `kind`, `payload` and `prev`, plus `actor` and `kid` if present. Leave out `hash` and `sig`.
2. Serialize that object as JSON:
   - keys sorted at every level;
   - separators `,` and `:` with no spaces;
   - non-ASCII characters written as raw UTF-8, not `\u` escapes;
   - no trailing newline.
3. `hash` is the lowercase hex SHA-256 of those bytes.

The chain is intact when every entry's `hash` matches step 3, every `prev` equals the previous entry's `hash`, and `seq` counts up from 1.

## Signatures

- **`kid`** is the first 16 hex characters of the SHA-256 of the raw 32-byte Ed25519 public key.
- **`sig`** is the Ed25519 signature (RFC 8032) over the 64 ASCII characters of `hash`, written as lowercase hex.

Rules a verifier must apply:

1. **An entry with a `kid` must have a valid `sig`.** `kid` is covered by the hash and `sig` is not, so deleting a signature doesn't break the chain. The leftover `kid` is the only evidence it was there. This rule holds without any key, so check it on every verification.
2. **Unsigned entries are allowed only *before* the first entry with a `kid`.** That's history from before signing was turned on. Once an entry names a key, every later entry must be signed too: a ledger never goes back from signed to unsigned.
3. **With a public key in hand,** every signed entry's `kid` must match it, and every `sig` must verify. A ledger with no signed entries at all fails. If you expected signatures and there are none, they may have been removed together with their `kid`s, which rule 1 can't see on its own; the broken hashes would, unless the whole ledger was rewritten. Use an anchor for that.

## Anchors

An anchor is `<seq>:<hash>` of an entry. It proves the history up to that entry is unchanged, if the entry at position `seq` still has that `hash`. If that entry is also the last one, nothing was added or removed after it (`verify --exact`).

## Worked example

These are the values `tests/test_known_answers.py` uses. The key is the RFC 8032 test-1 key, so they're reproducible.

**Entry 1**, canonical bytes:

```text
{"kind":"case.create","payload":{"id":"kat","title":"Résumé — test"},"prev":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"ts":"2026-10-22T00:00:00+00:00"}
```

```bash
printf '%s' '<the line above>' | sha256sum
# cb5d6982427a2469f5e726077a23382d7a127c1e5199fc9aeca69845dd2a4fde
```

**Key id** of the RFC 8032 test-1 public key:

```bash
printf d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a | xxd -r -p | sha256sum | cut -c1-16
# 21fe31dfa154a261
```

**Entry 2** (signed), canonical bytes:

```text
{"actor":"alex","kid":"21fe31dfa154a261","kind":"event.add","payload":{"decision":"Denied","id":"EVT-0001"},"prev":"cb5d6982427a2469f5e726077a23382d7a127c1e5199fc9aeca69845dd2a4fde","seq":2,"ts":"2026-10-22T00:00:01+00:00"}
```

```text
hash: b040e15ba2e1a5fa4aba8e8c843d5a8aacf11d86085da5c106f9504acfcc7e3a
sig:  b827ffcf8421a131cae6000aa2785a7f6ea9404d1435b31b3fd9dbfdb78a4ae6e1e5aef8cebd8c3c33174b835cce2f97d0083cdc5c8fb1ca09423eceec3db40b
```

To check a signature with OpenSSL, use the case's `signing-key.pub`, or a public key the owner gave you separately:

```bash
printf '%s' b040e15ba2e1a5fa4aba8e8c843d5a8aacf11d86085da5c106f9504acfcc7e3a > msg.txt
printf '%s' <sig hex> | xxd -r -p > sig.bin
openssl pkeyutl -verify -pubin -inkey signing-key.pub -rawin -in msg.txt -sigfile sig.bin
```

The anchor after entry 2 is `2:b040e15ba2e1a5fa4aba8e8c843d5a8aacf11d86085da5c106f9504acfcc7e3a`.

## Evidence files

Each `artifact` names a `stored_path` under `evidence/` and the file's `sha256`. Check each one with `sha256sum`. The `evidence/` folder should hold exactly the files the ledger lists.
