rule RisePro {
	meta:
		author = "ANY.RUN"
		description = "Detects RisePro (stealer version)"
		date = "2023-11-27"
		reference = "https://any.run/cybersecurity-blog/risepro-malware-communication-analysis/"
	strings:
		$ = { 74 2e 6d 65 2f 52 69 73 65 50 72 6f 53 55 50 50 4f 52 54 }
	condition:
		any of them
}
