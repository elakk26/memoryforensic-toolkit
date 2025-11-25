rule Suspicious_Packed_Code {
    meta:
        description = "Detects packed or obfuscated code patterns"
        severity = "high"

    strings:
        $pack1 = "UPX" nocase
        $pack2 = "ASPACK" nocase
        $pack3 = "PECompact" nocase
        $entropy = "high entropy" nocase

    condition:
        any of them
}

rule Suspicious_Memory_Write_Read {
    meta:
        description = "Detects suspicious memory operations"
        severity = "medium"

    strings:
        $mem1 = "WriteProcessMemory" nocase
        $mem2 = "ReadProcessMemory" nocase
        $mem3 = "VirtualAllocEx" nocase
        $mem4 = "GetModuleHandle" nocase

    condition:
        any of them
}

rule Suspicious_Anti_Debug {
    meta:
        description = "Detects anti-debugging techniques"
        severity = "high"

    strings:
        $debug1 = "IsDebuggerPresent" nocase
        $debug2 = "CheckRemoteDebuggerPresent" nocase
        $debug3 = "OutputDebugString" nocase
        $debug4 = "int 3" nocase

    condition:
        any of them
}

rule Suspicious_Rootkit_Behavior {
    meta:
        description = "Detects rootkit installation patterns"
        severity = "critical"
        tags = "critical"

    strings:
        $root1 = "ZwQuerySystemInformation" nocase
        $root2 = "NtSetInformationFile" nocase
        $root3 = "hook" nocase
        $root4 = "/proc/modules" nocase

    condition:
        any of them
}

rule Suspicious_Privilege_Escalation {
    meta:
        description = "Detects privilege escalation attempts"
        severity = "critical"
        tags = "critical"

    strings:
        $priv1 = "sudo" nocase
        $priv2 = "SYSTEM" nocase
        $priv3 = "0x0" nocase
        $priv4 = "setuid" nocase

    condition:
        any of them
}

rule Suspicious_Network_Beacon {
    meta:
        description = "Detects C2 command and control beacon patterns"
        severity = "critical"
        tags = "critical"

    strings:
        $beacon1 = "POST /api" nocase
        $beacon2 = "X-API-Key" nocase
        $beacon3 = "User-Agent" nocase
        $beacon4 = "Content-Type: application/json" nocase

    condition:
        any of them
}

rule Suspicious_File_Operations {
    meta:
        description = "Detects suspicious file operations"
        severity = "high"

    strings:
        $file1 = "/etc/passwd" nocase
        $file2 = "/etc/shadow" nocase
        $file3 = "C:\\Windows\\System32" nocase
        $file4 = "ntlm" nocase

    condition:
        any of them
}