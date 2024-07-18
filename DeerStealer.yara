rule DeerStealer {
    meta:
        author = "ANY.RUN"
        date = "2024-07-18"
        sha256 = "d9db8cdef549e4ad0e33754d589a4c299e7082c3a0b5efdee1a0218a0a1bf1ee"
    strings:
        $s1 = { 48 8b 84 24 [4] //MOV   RAX,qword ptr [RSP + 0x88]
                48 8b 84 24 [4] //MOV   RAX,qword ptr [RSP + 0x80]
                48 8b 44 [2]    //MOV   RAX,qword ptr [RSP + 0x78]
                48 8b 44 [2]    //MOV   RAX,qword ptr [RSP + 0x70]
                48 8b 05 [4]    //MOV   RAX,qword ptr [PTR_DAT_1402e2870]
                8b 08           //MOV   ECX,dword ptr [RAX]=>DAT_1402ec0b0
                e8 [4]          //CALL  KERNEL32.DLL::TlsGetValue
                48 8b [3]       //MOV   RCX,qword ptr [RSP + 0x28]
                8b 54 [2]       //MOV   EDX,dword ptr [RSP + 0x34]
                4c 8b [3]       //MOV   R8,qword ptr [RSP + 0x38]
                4c 8b [3]       //MOV   R9,qword ptr [RSP + 0x40]
                48 8b 05 [4]    //MOV   RAX,qword ptr [DAT_1402f00c8]
                48 83 c4 ??     //ADD   RSP,0x48
                48 ff e0}       //JMP   RAX

        $s2 = { 48 8b 44 24 ??  //MOV   RAX,qword ptr [RSP + local_50]
                48 8b 4c 24 ??  //MOV   RCX,qword ptr [RSP + local_58]
                ff d0           //CALL  RAX
                e9 [4]          //JMP   LAB_1400355c4
                48 8b 44 24 ??  //MOV   RAX,qword ptr [RSP + local_50]
                ff d0}          //CALL  RAX

    condition:
        uint16(0) == 0x5a4d and any of them
}