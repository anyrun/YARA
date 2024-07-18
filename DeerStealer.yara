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
                48 8b 05 }      //MOV   ECX,dword ptr [RAX]=>DAT_1402ec0b0
                  
        $s2 = { 48 8b 44 24 ??  //MOV   RAX,qword ptr [RSP + local_50]
                48 8b 4c 24 ??  //MOV   RCX,qword ptr [RSP + local_58]
                ff d0           //CALL  RAX
                e9 [4]          //JMP   LAB_1400355c4
                48 8b 44 24 ??  //MOV   RAX,qword ptr [RSP + local_50]
                ff d0}          //CALL  RAX

    condition:
        uint16(0) == 0x5a4d and any of them
}