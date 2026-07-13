rule yara_simulated_payroll_export
{
    meta:
        description = "Detect an inert incident-training artifact"
        author = "Vincent Plessy"
        mitre = "T1005"

    strings:
        $marker = "SIMULATED_INCIDENT_MARKER" ascii
        $payroll = "PAYROLL_EXPORT" ascii nocase
        $session = "SESSION_TOKEN_EXPOSED" ascii

    condition:
        $marker and 2 of ($payroll, $session)
}
