rule html_phishing_campaign {
    meta:

        author = "ANY.RUN"
        family = "phishing"
        description = "Detects phishing campaign"
        date = "2024-10-01"

    strings:	 

        $s0 = "<b>Ctrl + V</b>" ascii wide 
        $s1 = "<b>+ R</b>" ascii wide 
        $s2 = "<b>Ctrl</b> + <b>V</b>" ascii wide 
        $s3 = "\">R</kbd>" ascii wide 
        $s4 = "\">Enter</kbd>" ascii wide 
        $s5 = "\">Ctrl</kbd> + <kbd" ascii wide 
        $s6 = "hold the Windows Key <i" ascii wide 
        $s7 = "Perform the steps above to finish verification." ascii wide 
                
    condition: 
        2 of them 	 
} 
