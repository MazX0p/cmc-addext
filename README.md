# cmc-addext

I use the CMC `id-cmc-addExtensions` control to inject arbitrary X.509 extensions
into an AD CS certificate request. On an ESC1-shaped template, that lets a
low-privileged domain user forge a certificate whose Subject Alternative Name and
whose `szOID_NTDS_CA_SECURITY_EXT` SID both point at Administrator - and PKINIT to
Domain Admin on a fully patched CA and DC with
`StrongCertificateBindingEnforcement = 2`.

Full writeup, with the disassembly and the reasoning:
https://0xmaz.me/posts/certsrv-id-cmc-addExtensions-KB5014754-bypass/

Reverse-engineering notes (functions, offsets, both binaries): [`REVERSING.md`](REVERSING.md).

## How it works

Two defects, chained.

`certsrv.exe` routes request extensions through a dispatcher that masks the caller
flag with `& 0xf0000` and recognises only two allowlists (`0x50000` and `0x90000`).
The `id-cmc-addExtensions` handler calls it with `0x80002`, and
`0x80002 & 0xf0000 = 0x80000` - neither value - so no allowlist runs. Every
extension I put in the CMC control reaches `SetCertificateExtension`, including the
SAN and `szOID_NTDS_CA_SECURITY_EXT`. The signer only needs a certificate the CA
itself issued (`CryptMsgGetAndVerifySigner` with `CMSG_SIGNER_ONLY_FLAG` checks the
signature, not the chain), so `--auto-signer` enrolls a throwaway to sign with.

`certpdef.dll` is supposed to stamp the requester's real SID into that extension -
the KB5014754 defence. On the enrollee-supplies-subject path it doesn't generate
anything; it copies the SID out of the request. Since the first defect lets me put
any SID in the request, I supply the Administrator's SID next to the Administrator
UPN, and the KDC's strong binding check passes.

## Requirements on the target

- An ESC1-shaped template: `ENROLLEE_SUPPLIES_SUBJECT`, a `clientAuth` EKU, enroll
  rights for the low-privileged user, and no `SUBJECT_ALT_REQUIRE_UPN`. No
  default-published template has this shape - the built-ins carry
  `REQUIRE_UPN`/`REQUIRE_DNS`, which rebind the SAN and SID to the caller. The
  point is that KB5014754 was documented as making a leftover ESC1 template
  survivable; on this path it doesn't.
- MS-ICPR (RPC, port 135) to the CA. CES is optional.
- Any low-privileged domain account (to auto-enroll the throwaway signer).

## Install

```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# certipy-ad and impacket (certipy, secretsdump.py) on PATH for auth + DCSync
```

## Use

```
python3 cmc_addext.py --auto-signer \
    --ca-host <ca> --ca-name <CA-NAME> --template <ESC1_TEMPLATE> \
    --inject-upn administrator@<domain> \
    --dc-ip <dc> --dc-user <low_user> --dc-pass '<pass>' \
    --out forged_admin.pfx --pfx-pass addext

python3 verify_cert_sid.py forged_admin.pfx addext

certipy auth -pfx forged_admin.pfx -password addext \
    -dc-ip <dc> -domain <domain> -username administrator

secretsdump.py -hashes :<nthash> <domain>/administrator@<dc> -just-dc-user krbtgt
```

`--inject-sid` is resolved from AD automatically when `--dc-ip`/`--dc-pass` are
set; pass it to force a specific value.

## Confirming the mechanism

I keep `verify_cert_sid.py` separate from the builder on purpose - it parses the
issued PFX with no shared code, so nothing that created the certificate gets to
grade it. Three requests, changing only what I inject, show exactly where the SID
comes from:

| Inject | NTDS SID the CA writes | Reading |
|--------|------------------------|---------|
| Admin UPN, no SID | extension absent | the CA stamps no requester SID on this path |
| Admin UPN + a RID that maps to no account | that RID, verbatim | the request owns the SID field |
| Admin UPN + Administrator's SID | Administrator's RID | matched pair → PKINIT as Administrator |

The first request alone is decisive: a fully patched CA issues a clientAuth
certificate with no `szOID_NTDS_CA_SECURITY_EXT` in it, so the KB5014754 stamp
never ran.

## Mitigation

1. Remove the ESC1 template. If a low-privileged principal can enroll a
   `clientAuth` template with `ENROLLEE_SUPPLIES_SUBJECT` and no `REQUIRE_UPN`,
   that is the hole to close, and it's the only complete fix today.
2. If you must keep a `clientAuth` template, set `SUBJECT_ALT_REQUIRE_UPN` on it -
   that moves `certpdef.dll` onto the branch that rebinds SAN and SID to the caller.
3. Require manager approval or an RA signature (`msPKI-RA-Signature > 0`).
4. Restrict MS-ICPR to the CA. Reduces surface; does not remove the defect.

## Files

- `cmc_addext.py` - builds and submits the CMC (RPC or CES)
- `verify_cert_sid.py` - independent reader for the issued PFX
- `REVERSING.md` - certsrv.exe + certpdef.dll analysis, functions and offsets
- `full-chain-transcript.txt` - a recorded run, low-priv to krbtgt

---

Mohamed Alzhrani (@0xmaz) · https://0xmaz.me · For authorized testing and research
only, against systems you own or are explicitly permitted to test.
