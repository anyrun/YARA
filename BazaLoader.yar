rule BazaLoader
{
	meta:
		author = "ANY.RUN"
		description = "Detects BazaLoader"
		date = "2024-01-19"
		hash1 = "55dfa7907b2874b0fab13c6fc271f0a592b60f320cd43349805bd74c41a527d3"
		url = "https://app.any.run/tasks/50e879cc-2abd-49d2-857a-0e7bb21b166f"
		unpacked_example = "https://app.any.run/tasks/7431c3f9-7a87-41c2-ac1c-c00e391414d5"

	strings:
		// intentional mistakes in the path
		$x1 = "\\\\?\\C:\\Windows \\System32\\WINMM.dll" fullword wide
		$x2 = "C:\\Windows \\System32\\winSAT.exe" fullword wide
		// target file and directory
		$x3 = "c:\\windows\\system\\svchost.exe" fullword ascii
		// PDB parts
		$x4 = "\\Release\\sloader.pdb" ascii
		$x5 = "\\for_re_nat\\v5x_5" ascii
		// log messages
		$x6 = "[*] Data + param_offset(%d)+JPG_OFFSET:" fullword ascii
		$x7 = "[+] We get next CFG data from server:" fullword ascii
		// URL part
		$x8= "/?a=iamok_%s_%s" ascii
		// nickname
		$x9 = "barabaka666" fullword ascii

		$s_dll = "/steel_.dll" fullword ascii
		$s_mut = "Global\\AlreadyExist" fullword ascii

		$cmd1 = "advfirewall firewall add rule name=\"" wide
		$cmd2 = "WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName" fullword ascii
		$cmd3 = "schtasks /delete /TN \"" ascii
		$cmd4 = "schtasks /create /sc minute /ED \"" ascii
		$cmd5 = "Add-MpPreference -ExclusionPath \\\\?\\C:\\" wide

		$log1 = "[+] Mutex created " fullword ascii
		$log0 = "[*] UAC is bypassed now!" fullword ascii

		$url1 = ".onion/index.php" ascii
		$url2 = "/getlog.php?a=%s" ascii

		$tor = "TOR_GET HEADER:" fullword ascii

	condition:
		uint16(0) == 0x5a4d
		and (
			1 of ($x*)
			or (1 of ($s_*) and 3 of them)
			or 7 of them
		)
}