# YARA

This repository contains a curated collection of YARA rules designed to detect a wide range of malware families, phishing campaigns, and other malicious artifacts. 

The rules are regularly updated to reflect the latest malware trends observed in the wild, with a focus on accuracy and reducing false positives. 

This project is intended for:  

- Malware researchers — to speed up classification and detection of samples.  
- Threat hunters and SOC analysts — to enrich detection capabilities and incident response.  
- Security engineers — to integrate YARA detection logic into larger defense systems. 

## Code of Conduct
This project and everyone participating in it is governed by our Code of Conduct.
By participating, you are expected to uphold this code.

## Contributing
We welcome contributions! Your input helps us keep the rule set accurate and up to date. If you'd like to contribute, here’s how you can get involved:

- Open an issue to discuss a rule idea or improvement.  
- Submit a PR with:  
  - The rule file (use clear naming and include meta fields such as `description`, `author`, `date`, `reference`).  
  - A brief rationale and, if possible, example detections/benign checks to minimize FPs.

## See YARA in Action
To better understand how this YARA rule detects Sakula malware, you can observe its behavior in real time using [ANY.RUN’s Interactive Sandbox](https://any.run/?utm_source=github&utm_medium=readme&utm_campaign=yara&utm_content=linktolanding).
![Sakula malware detected by YARA inside ANY.RUN sandbox](https://any.run/cybersecurity-blog/wp-content/uploads/2025/01/image-1-2048x1173.png)
This analysis session showcases the malware’s activity and how the rule effectively identifies its patterns.
ANY.RUN’s interactive sandbox is a dynamic environment where cybersecurity teams can analyze files and observe their behavior in real time. Unlike traditional sandboxes, ANY.RUN lets users interact with the malware, providing deeper insights and faster results. 

YARA is an inseparable part of this process. By integrating YARA rules into the sandbox, ANY.RUN identifies malicious patterns in files and processes with precision and speed. 

ANY.RUN experts are constantly adding new YARA rules to the core of our malware sandbox, making the analysis process faster and saving security teams loads of time.  

You can easily upload any suspicious file or link into the sandbox, and during the analysis, YARA rules will kick in. If there’s malware hiding in your file or link, the sandbox will spot it for you. 

For example, after analyzing the following sample in the ANY.RUN sandbox, the process fgfkjsh.exe was flagged as malicious with the “MassLogger” tag.
![Malicious file detected by ANY.RUN sandbox](https://any.run/cybersecurity-blog/wp-content/uploads/2025/01/image2-1.png)

By clicking on the process located on the right side of the screen, the sandbox displays the message “MASSLOGGER has been detected (YARA).”
![Masslogger has been detected by YARA rule](https://any.run/cybersecurity-blog/wp-content/uploads/2025/01/image3-1.png)

## YARA Search in TI Lookup
YARA rules aren’t just limited to the sandbox — they’re also available in [ANY.RUN’s Threat Intelligence (TI) Lookup](https://any.run/threat-intelligence-lookup/?utm_source=github&utm_medium=readme&utm_campaign=yara&utm_content=linktolanding).  
This tool lets you search a massive database of malware artifacts using YARA rules, helping you find connections between known threats and your own files.  

It’s perfect for teams handling big datasets or looking to spot trends in cyber threats.  
By combining YARA’s precision with the power of the sandbox and TI Lookup, ANY.RUN gives businesses a complete solution to fight evolving threats.

## Useful links
[Malware Analysis in ANY.RUN: The Ultimate Guide](https://any.run/cybersecurity-blog/malware-analysis-in-a-sandbox/?utm_source=github&utm_medium=readme&utm_campaign=yara_readme&utm_content=linktoblog&utm_term=061025) 

[Malware Analysis articles (case studies, walkthroughs)](https://any.run/cybersecurity-blog/category/malware-analysis/?utm_source=github&utm_medium=readme&utm_campaign=yara_readme&utm_content=linktoblog&utm_term=061025) 
 
## Contact us 
If you'd like to try out ANY.RUN, you can [request a trial here](https://any.run/demo/?utm_source=github&utm_medium=readme&utm_campaign=yara_readme&utm_content=linktodemo&utm_term=061025).

Support inquiries – support@any.run 

Public relations and partnerships – pr@any.run 
