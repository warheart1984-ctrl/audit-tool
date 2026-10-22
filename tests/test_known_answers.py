"""Known-answer tests: the ledger format and signatures checked against values
computed OUTSIDE this tool.

Every other test compares the tool with itself. If the format drifted (other
JSON separators, \\u escapes, another hash, signing different bytes), the tool
would still agree with itself and every other test would pass, but anyone
verifying a ledger independently would get different answers. The mutation run
showed exactly that: six such format defects survived until these tests existed.

Where the expected values come from (no code from this project was used):

* Canonical entry bytes were written by hand from docs/LEDGER_FORMAT.md
  (sorted keys, "," and ":" separators, UTF-8, no trailing newline).
* HASH_A / HASH_B:   sha256sum (GNU coreutils 8.32) over those bytes.
* KID:               printf '<RFC public key hex>' | xxd -r -p | sha256sum, first 16 hex.
* SIG_B:             openssl pkeyutl -sign -rawin (OpenSSL 3.5.7) with the RFC 8032
                     test-1 key, over the 64 ASCII characters of HASH_B; checked
                     with openssl pkeyutl -verify.
* RFC_*:             RFC 8032 section 7.1, tests 1 and 2 (test 2 also reproduced
                     with OpenSSL).
"""

from __future__ import annotations

import json

import pytest

from audit_tool import ledger as ledger_mod
from audit_tool.ledger import GENESIS, Ledger, _entry_hash

# --- Externally computed values ------------------------------------------------

RFC1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RFC1_SIG_EMPTY = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                  "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
RFC2_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
RFC2_PUB = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
RFC2_MSG = "72"
RFC2_SIG = ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")

ENTRY_A = {"seq": 1, "ts": "2026-10-22T00:00:00+00:00", "kind": "case.create",
           "payload": {"id": "kat", "title": "Résumé — test"}, "prev": "0" * 64}
HASH_A = "cb5d6982427a2469f5e726077a23382d7a127c1e5199fc9aeca69845dd2a4fde"

KID = "21fe31dfa154a261"
ENTRY_B = {"seq": 2, "ts": "2026-10-22T00:00:01+00:00", "kind": "event.add",
           "payload": {"id": "EVT-0001", "decision": "Denied"}, "prev": HASH_A,
           "actor": "alex", "kid": KID}
HASH_B = "b040e15ba2e1a5fa4aba8e8c843d5a8aacf11d86085da5c106f9504acfcc7e3a"
SIG_B = ("b827ffcf8421a131cae6000aa2785a7f6ea9404d1435b31b3fd9dbfdb78a4ae6"
         "e1e5aef8cebd8c3c33174b835cce2f97d0083cdc5c8fb1ca09423eceec3db40b")


def _keys():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(RFC1_SEED))


# --- Hashing ---------------------------------------------------------------------

def test_entry_hash_matches_sha256sum_of_the_canonical_bytes():
    assert _entry_hash(ENTRY_A) == HASH_A  # non-ASCII title pins UTF-8 without \u escapes


def test_actor_and_kid_are_hashed_as_specified():
    assert _entry_hash(ENTRY_B) == HASH_B


def test_chain_starts_from_64_zeros():
    assert GENESIS == "0" * 64


# --- Keys and signatures -----------------------------------------------------------

def test_rfc8032_vectors_through_the_signing_library():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from audit_tool.ledger import public_bytes

    k1 = _keys()
    assert public_bytes(k1.public_key()).hex() == RFC1_PUB
    assert k1.sign(b"").hex() == RFC1_SIG_EMPTY
    k2 = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(RFC2_SEED))
    assert public_bytes(k2.public_key()).hex() == RFC2_PUB
    assert k2.sign(bytes.fromhex(RFC2_MSG)).hex() == RFC2_SIG


def test_key_id_matches_sha256sum_of_the_raw_public_key():
    from audit_tool.ledger import key_id

    assert key_id(_keys().public_key()) == KID


# --- Whole ledger, both directions ---------------------------------------------------

def test_tool_writes_exactly_the_externally_computed_ledger(tmp_path, monkeypatch):
    """Write side: with the clock pinned, the tool must produce the same hashes and signature."""
    key = _keys()
    stamps = iter([ENTRY_A["ts"], ENTRY_B["ts"]])
    monkeypatch.setattr(ledger_mod, "now_iso", lambda: next(stamps))
    path = tmp_path / "ledger.jsonl"
    a = Ledger(path).append("case.create", ENTRY_A["payload"])
    b = Ledger(path, signer=key, actor="alex").append("event.add", ENTRY_B["payload"])
    assert a["prev"] == "0" * 64 and a["hash"] == HASH_A
    assert b["kid"] == KID and b["hash"] == HASH_B
    assert b["sig"] == SIG_B  # Ed25519 is deterministic, so OpenSSL's signature must match exactly


def test_tool_verifies_a_ledger_built_entirely_outside_it(tmp_path):
    """Read side: a ledger assembled from external values must verify, signature included."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    path = tmp_path / "ledger.jsonl"
    lines = [dict(ENTRY_A, hash=HASH_A), dict(ENTRY_B, hash=HASH_B, sig=SIG_B)]
    path.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in lines) + "\n", encoding="utf-8")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(RFC1_PUB))
    checker = Ledger(path, verify_key=pub)
    assert checker.verify() == []
    assert checker.anchor() == f"2:{HASH_B}"
