/*
 * eicar_test_string.yar — the industry-standard EICAR antivirus test file signature.
 * https://www.eicar.org/download-anti-malware-testfile/ — a publicly documented, universally
 * recognized, harmless string every antivirus engine detects on purpose. Bundled here so the
 * YARA scanning path is PROVABLE end-to-end without needing (or shipping) any real malware
 * sample — matches the task's own "bundle a couple of benign test rules" bar.
 */
rule Eicar_Test_String : test benign
{
    meta:
        description = "EICAR standard antivirus test string (harmless, publicly documented)"
        severity = "informational"
        author = "HookProbe OS"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
