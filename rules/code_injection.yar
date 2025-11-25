rule Injection_Shellcode_Pattern {
    meta:
        description = "Detects common shellcode patterns"
        severity = "critical"
        tags = "critical"

    strings:
        $shellcode1 = {90 90 90} // NOP sled
        $shellcode2 = {CC CC CC} // INT3 breakpoint
        $shellcode3 = "xFFxE4" // JMP ESP
        $shellcode4 = "x58x58x58" // Three POPs

    condition:
        any of them
}

rule Injection_Return_Oriented {
    meta:
        description = "Detects Return-Oriented Programming patterns"
        severity = "critical"
        tags = "critical"

    strings:
        $rop1 = "xC3" // RET instruction
        $rop2 = {58 C3} // POP + RET
        $rop3 = "gadget" nocase
        $rop4 = "ROP" nocase

    condition:
        any of them
}

rule Injection_Self_Modifying_Code {
    meta:
        description = "Detects self-modifying code patterns"
        severity = "high"

    strings:
        $smc1 = "memcpy(" nocase
        $smc2 = "memmove(" nocase
        $smc3 = "code" nocase
        $smc4 = "modify" nocase

    condition:
        any of them
}

rule Injection_Thread_Hijacking {
    meta:
        description = "Detects thread hijacking patterns"
        severity = "high"

    strings:
        $thread1 = "SuspendThread" nocase
        $thread2 = "SetThreadContext" nocase
        $thread3 = "ResumeThread" nocase
        $thread4 = "pthread_create" nocase

    condition:
        any of them
}

rule Injection_Heap_Spray {
    meta:
        description = "Detects heap spray attack patterns"
        severity = "high"

    strings:
        $heap1 = "malloc(" nocase
        $heap2 = "new" nocase
        $heap3 = "0x0c0c0c0c" nocase
        $heap4 = "spray" nocase

    condition:
        any of them
}

rule Injection_Stack_Overflow {
    meta:
        description = "Detects stack overflow patterns"
        severity = "critical"
        tags = "critical"

    strings:
        $stack1 = "alloca(" nocase
        $stack2 = "variable length array" nocase
        $stack3 = "overflow" nocase
        $stack4 = "esp" nocase

    condition:
        any of them
}

rule Injection_Hook_Installation {
    meta:
        descript
        ion = "Detects API hook installation"
        severity = "high"

    strings:
        $hook1 = "SetWindowsHookEx" nocase
        $hook2 = "SetWinEventHook" nocase
        $hook3 = "hook" nocase
        $hook4 = "detour" nocase

    condition:
        any of them
}