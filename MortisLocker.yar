rule MortisLocker
{
	meta:
		author = "ANY.RUN"
		description = "Detects MortisLocker ransomware"
		date = "2023-10-05"
		reference = "https://twitter.com/MalGamy12/status/1709475837685256466"
		hash1 = "a5012e20342f4751360fd0d15ab013385cecd2a5f3e7a3e8503b1852d8499819"
		hash2 = "b6a4331334a16af65c5e4193f45b17c874e3eff8dd8667fd7cb8c7a570e2a8b9"
		hash3 = "c6df9cb7c26e0199106bdcd765d5b93436f373900b26f23dfc03b8b645c6913f"
		hash4 = "dac667cfc7824fd45f511bba83ffbdb28fa69cdeff0909979de84064ca2e0283"
	strings:
		$malname = "MortisLocker" fullword ascii

		$app_policy = "AppPolicyGetProcessTerminationMethod" fullword ascii

		$dbg_1 = "C:\\Users\\Admin\\OneDrive\\Desktop\\Test" fullword ascii
		$dbg_2 = "C:\\Users\\Admin\\source\\repos\\Mortis\\Release\\" fullword ascii

		$ext_susp_1 = ".Mortis" fullword ascii
		$ext_susp_2 = ".tabun" fullword ascii

		$dir_susp_1 = "config.msi" fullword ascii
		$dir_susp_2 = "recycle.bin" fullword ascii
		$dir_susp_3 = "windows.old" fullword ascii
		$dir_susp_4 = "$windows.~ws" fullword ascii
		$dir_susp_5 = "$windows.~bt" fullword ascii
		$dir_susp_6 = "msocache" fullword ascii
		$dir_susp_7 = "perflogs" fullword ascii

		$log_bcrypt = /BCrypt[\w]+ failed with error code:/ fullword ascii
		$log_drive_1 = "[i] Encrypting Logical Drives:" fullword ascii
		$log_drive_2 = "[-] No drives found." fullword ascii
		$log_share_1 = "[i] Encrypting Network Shares:" fullword ascii
		$log_share_2 = "[!] Failed to enumerate network shares:" fullword ascii
		$log_share_3 = "[-] No network shares found." fullword ascii
		$log_file_1 = "Encryption failed for file:" fullword ascii
		$log_file_2 = "Encryption successful. Encrypted file:" fullword ascii
		$log_file_3 = "Failed to open output file:" fullword ascii
		$log_file_4 = "Failed to rename file:" fullword ascii
		$log_file_5 = "File is empty:" fullword ascii
		$log_rbin_1 = "[+] Emptied Recycle Bin." fullword ascii
		$log_rbin_2 = "Recycle Bin emptied successfully." fullword ascii
		$log_rbin_3 = "[!] Failed to Empty Recycle Bin." fullword ascii
		$log_rbin_4 = "Failed to empty Recycle Bin." fullword ascii
		$log_priv_1 = "[+] Enabled Privileges." fullword ascii
		$log_priv_2 = "[!] Failed to enable privileges." fullword ascii
		$log_aes_1 = "[*] AES Key:" fullword ascii
		$log_aes_2 = "[i] AES Key:" fullword ascii
		$log_aes_3 = "[!] Failed to generate AES Key." fullword ascii
		$log_folder = "[*] Ignored Folder:" fullword ascii
		$log_lock = "[+] Locked:" fullword ascii
		$log_msg_1 = "cryptDir execution time:" fullword ascii
	condition:
		uint16(0) == 0x5A4D and
		(
			2 of ($malname, $app_policy, $dbg_*) or
			1 of ($malname, $app_policy, $dbg_*) and
			(
				3 of ($log_*) or
				6 of ($dir_susp_*, $ext_susp_*)
			)
		)
}
