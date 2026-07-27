#!/usr/bin/env python3
"""
verify_cert_sid.py - read a PFX and print its Subject, SAN UPN, and the
szOID_NTDS_CA_SECURITY_EXT SID (1.3.6.1.4.1.311.25.2), exactly as they sit in
the cert. I keep this separate from the PoC on purpose: nothing that built the
cert gets to grade it.

    python3 verify_cert_sid.py <file.pfx> [pfx_password]

Mohamed Alzhrani (@0xmaz) - https://0xmaz.me
"""
import sys
import re
import struct
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding

NTDS_SEC_EXT = "1.3.6.1.4.1.311.25.2"
UPN_OTHERNAME = "1.3.6.1.4.1.311.20.2.3"


def decode_binary_sid(b: bytes):
    if len(b) < 8:
        return None
    sub_count = b[1]
    authority = int.from_bytes(b[2:8], "big")
    subs = [struct.unpack("<I", b[8 + 4 * i:12 + 4 * i])[0] for i in range(sub_count)]
    return f"S-{b[0]}-{authority}-" + "-".join(str(s) for s in subs)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    pfx_path = sys.argv[1]
    pwd = (sys.argv[2] if len(sys.argv) > 2 else "").encode()

    _, cert, _ = pkcs12.load_key_and_certificates(open(pfx_path, "rb").read(), pwd)
    der = cert.public_bytes(Encoding.DER)

    print(f"Subject : {cert.subject.rfc4514_string()}")
    print(f"Serial  : {cert.serial_number:x}")

    upn = None
    for ext in cert.extensions:
        if ext.oid.dotted_string == "2.5.29.17":
            for gn in ext.value:
                try:
                    if gn.type_id.dotted_string == UPN_OTHERNAME:
                        raw = gn.value.value if hasattr(gn.value, "value") else gn.value
                        upn = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                except Exception:
                    pass
    print(f"SAN UPN : {upn}")

    sid, fmt = None, None
    for ext in cert.extensions:
        if ext.oid.dotted_string == NTDS_SEC_EXT:
            val = ext.value.value
            m = re.search(rb"S-1-5-21-[0-9-]+", val)
            if m:
                sid, fmt = m.group().decode(), "ASCII"
            else:
                idx = val.find(bytes.fromhex("010500000000000515"))
                if idx >= 0:
                    sid, fmt = decode_binary_sid(val[idx:idx + 28]), "BINARY"
    if sid:
        print(f"NTDS SID: {sid}  [{fmt}]")
    else:
        print("NTDS SID: ABSENT (no szOID_NTDS_CA_SECURITY_EXT in this certificate)")


if __name__ == "__main__":
    main()
