# Reverse engineering notes

Where the two bugs actually live, with the functions and offsets so you can check
me in your own Ghidra. Everything here is from the live CA binaries, SHA-verified
off the host: `certsrv.exe 10.0.17763.8385` and the policy module
`certpdef.dll 10.0.17763.6893`. Image base `0x140000000` for `certsrv.exe`,
`0x180000000` for `certpdef.dll`.

Mohamed Alzhrani (@0xmaz) - https://0xmaz.me

## Bug 1 - `certsrv.exe`: `id-cmc-addExtensions` skips the extension allowlist

The request-extension dispatcher (`FUN_14002b090`) masks the caller flag with
`& 0xf0000` and only recognises two allowlist worlds:

```
; FUN_14002b090 - request-extension dispatcher
14002b0dd: AND  R15D, 0xf0000       ; mask = flag & 0xf0000
14002b0e4: CMP  R15D, 0x50000       ; Allowlist A (AIA/CDP/AKI/SKI/CAVersion)
14002b0eb: JNZ  0x14002b13f
14002b13f: CMP  R15D, 0x90000       ; Allowlist B (SKI only)
14002b146: JNZ  0x14002b198         ; neither -> no list is consulted
14002b287: CALL <ICertServerPolicy::SetCertificateExtension>
```

The `id-cmc-addExtensions` handler (`FUN_140030a30`, which `strcmp`s the control
OID against `1.3.6.1.5.5.7.7.8`) calls the dispatcher with flag `0x80002`
(call at `0x140030b43`):

```
0x80002 & 0xf0000 = 0x80000        ; != 0x50000 and != 0x90000
-> every extension injected via the CMC control reaches SetCertificateExtension
```

Signer check: the CMC message is decoded and its signer verified in `FUN_14003151c`
via `CryptMsgGetAndVerifySigner(..., CMSG_SIGNER_ONLY_FLAG /* 4 */, ...)` - signature
only, not chain or purpose. Any CA-issued cert (a throwaway auto-enrolled one
included) can sign the CMC.

## Bug 2 - `certpdef.dll`: the KB5014754 SID stamp is copied from the request, not generated

The stamp OIDs live only in `certpdef.dll` (the default policy module), not in
`certca.dll` (which merely *reads* SAN/UPN, `2.5.29.17` / `1.3.6.1.4.1.311.20.2.3`):

```
0x180025590  "1.3.6.1.4.1.311.25.2"     (szOID_NTDS_CA_SECURITY_EXT)
0x1800255c0  "1.3.6.1.4.1.311.25.2.1"   (szOID_NTDS_OBJECTSID)
```

Both are referenced by exactly one function, the stamp writer `FUN_180012ee8`
(called from the VerifyRequest pipeline `FUN_18001164c` at `0x180011852`):

```
; FUN_180012ee8   (RSI = request/context object)
180012f2d: TEST dword [RSI+0x14], 0x80000  ; CT_FLAG_NO_SECURITY_EXTENSION -> skip + log
180012f34: JZ   0x180012f4d
180012f42: CALL <log>   "Skipping the addition of security extension as per the template config."
180012f48: JMP  0x18001318c

180012f4d: MOV  EBX, 1
180012f52: TEST byte [RSI+0x18], BL        ; bit0 = "request supplies its own subject/exts"
180012f55: JZ   0x180012ffe                ;  bit0==0 -> GENERATE caller SID (secure path)
;  fall through                            ;  bit0==1 -> TRUST the request

; --- trust path (bit0 == 1) ---
180012f69: CALL 0x180003ed4                ; read request's own 1.3.6.1.4.1.311.25.2
180012f70: CMP  EAX, 0x80094004            ; absent?
180012f75: JNZ  0x180012f7e
180012f77: XOR  EBX, EBX                    ;  -> success, stamp NOTHING   (== experiment A)
180012f79: JMP  0x18001318c
;  present -> keep the request's value, only clear flag bit 0x2   (== experiment B)

; --- generate path (bit0 == 0, @0x180012ffe) ---
18001302f: CALL 0x18000f04c                ; fetch the AUTHENTICATED caller's SID string
180013159: CALL 0x180003f78                ; write 1.3.6.1.4.1.311.25.2 with that SID (honest KB5014754)
```

The caller branches on the same bit:

```c
// FUN_18001164c
if ((*(uint *)(param_1 + 0x18) & 1) == 0) {
    FUN_18000e3d4(...);   // derive requester identity extensions (normal path)
} else {
    FUN_180012780(...);
    FUN_180012ee8(...);   // stamp writer -> TRUST branch
}
```

`[RSI+0x18] & 1` is the enrollee-supplies-subject context. On an ESC1 template
(`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, no `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN`)
submitted over MS-ICPR, that bit is set: the CA never generates the caller's SID,
it copies whatever `szOID_NTDS_CA_SECURITY_EXT` the request supplied (bug 1 lets the
request supply any value, or none). Templates with `REQUIRE_UPN` take the other
branch and rewrite SAN + SID to the caller, which is why the attack only works on
the ESC1 shape.

## Mapping to the control experiments

| Experiment | Request carries | Trust-path result | Observed in issued cert |
|-----------|-----------------|-------------------|-------------------------|
| A | admin UPN, no SID ext | `FUN_180003ed4` returns `0x80094004` -> stamp nothing | **no** `szOID_NTDS_CA_SECURITY_EXT` |
| B | admin UPN + SID RID 31337 | value kept, one flag bit cleared | SID = `...-31337` |
| Attack | admin UPN + admin SID | value kept | SID = `...-500` -> PKINIT as admin |
