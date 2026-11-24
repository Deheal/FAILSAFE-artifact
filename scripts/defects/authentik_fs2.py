INJECT_MARKER = ("    try:\n"
                 "        authentication_verification = verify_authentication_response(\n"
                 "            credential=credential,\n"
                 "            expected_challenge=challenge,\n"
                 "            expected_rp_id=get_rp_id(request),\n"
                 "            expected_origin=get_origin(request),\n"
                 "            credential_public_key=base64url_to_bytes(device.public_key),\n"
                 "            credential_current_sign_count=device.sign_count,")

INJECT_BLOCK = ('''    # FAILSAFE defect injection FS-2 (docs/defect_injection.md): CVE pattern (counter variant).
    import struct as _fs2_struct

    _fs2_prior = device.sign_count
    _fs2_ad = credential.response.authenticator_data
    if _fs2_ad is not None and len(_fs2_ad) >= 37:
        _fs2_count = _fs2_struct.unpack(">I", _fs2_ad[33:37])[0]
        if _fs2_count > device.sign_count:
            with audit_ignore():
                device.set_sign_count(_fs2_count)   # persist BEFORE verification
    try:
        authentication_verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_rp_id(request),
            expected_origin=get_origin(request),
            credential_public_key=base64url_to_bytes(device.public_key),
            credential_current_sign_count=_fs2_prior,''')


def patch_text(src: str) -> str:
    assert src.count(INJECT_MARKER) == 1, "주입 지점이 유일하지 않음"
    return src.replace(INJECT_MARKER, INJECT_BLOCK)
