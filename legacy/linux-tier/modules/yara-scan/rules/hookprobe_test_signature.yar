/*
 * hookprobe_test_signature.yar — a second, HookProbe-own benign test signature (independent of
 * the EICAR string), proving multi-rule loading and giving verification-engineer/an operator a
 * marker they can drop into a throwaway file to prove the scan path fires without needing EICAR.
 */
rule HookProbe_Yara_Test_Signature : test benign
{
    meta:
        description = "HookProbe YARA path self-test marker (harmless, no real malware content)"
        severity = "informational"
        author = "HookProbe OS"
    strings:
        $marker = "HOOKPROBE-YARA-TEST-SIGNATURE-88f3c2"
    condition:
        $marker
}
