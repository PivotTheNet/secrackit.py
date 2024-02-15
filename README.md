# secrackit.py
**secrackit.py** automates the following into a single command:
1. Windows SMB auth checks (CrackMapExec)
2. Dumps and parses NTLM hashes from secrets (Impacket-secretsdump)
3. Cracks NTLM hashes (Hashcat)
4. Exports both tool and command outputs to directory.
---
### Table of Contents
- [Script execution explained](https://github.com/PivotTheNet/secrackit.py/tree/main#script-execution-explained)
- [Prereqs](https://github.com/PivotTheNet/secrackit.py/tree/main#script-prerequisites)
- [Q/A](https://github.com/PivotTheNet/secrackit.py/tree/main#qa)
- [Shout-outs](https://github.com/PivotTheNet/secrackit.py/tree/main#shout-outs)
- [Disclaimer](https://github.com/PivotTheNet/secrackit.py/tree/main#disclaimer)


---

### Script execution explained:  

Example syntax using all optional arguments:  
`./secrackit.py DC-IP domain.name IPs.txt accountname pw badpassword123 -localauth -out_dir ~/Desktop/toolsoutput -wordlist ~/Desktop/wordlists/customwordlist.txt -rule ~/media/hashcatrules/TwoRule.rule`


<ins>Required positional arguments:</ins>
1. `DC-IP` - IP address of the domain controller.
2. `domain.name` - Active directory domain name.
3. `IP` *or* `CIDR` *or* `/File.txt` - Target IPs. Either a single IP, single networkID(CIDR), or the location of a file containing one IP per line.
4. `AccountName` - Single account name used for either local or domain authentication.
5. `pw` *or* `ntlm` - Specify whether a password (`pw`) or NTLM hash (`ntlm`) will be inputted.
6. `Password` *or* `NTLM hash` - Value of password **or** NTLM hash. If `pw` argument passed, provide a cleartext password. If `ntlm` argument passed, provide a NTLM hash.

<ins>Optional arguments:</ins>  
- `-localauth` - Use local authentication against targets. (Default is domain authentication) 
- `-out_dir` - Specify directory location for results. (Defaults to the directory secrackit.py is ran from)
- `-wordlist` - Specify custom wordlist location for Hashcat. (Default is `/usr/share/wordlists/rockyou.txt`)
- `-rule` - Specify rule location for Hashcat. (Default is no rule)
- `-h` - Cancels script execution and displays help details.

---

### Script prerequisites?
1. Packages `crackmapexec`, `impacket-secretsdump`, and `hashcat` must be installed and present in your $PATH.
2. If you aren't specifying a custom wordlist, via `-wordlist`, secrackit.py will default to rockyou.txt located at `/usr/share/wordlists/rockyou.txt`.
3. If you're on Kali, simply do the following to install and prep the three required tools:  
   i. `sudo apt update && sudo apt install crackmapexec python3-impacket hashcat`  
   ii. If you haven't ran these tools before, run each tool once before running secrackit.py. Some tools create databases, etc on their first run and this may cause issues for secrackit.py.(never tested)  

---

### Q/A
**Story behind the script?**
- *After some AD labs online and at home, I found myself running these three scripts over and over. I also wanted to organize any dumped hashes by prepending IP, SAM or NTDS, etc to the NTLM hashes.*

**Why so many comments? XD**
- *I'm learning python and it helps when I come back to it later. Maybe it'll help others too. :)*

---

### Shout-outs

Thanks to the creators of the following tools! You're awesome!
- CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
- Impacket-secretsdump - https://github.com/fortra/impacket
- Hashcat - https://github.com/hashcat/hashcat

---

### DISCLAIMER
 1. I take zero(0) responsibility for your actions if and when you ever use(execute) "secrackit.py".
 2. Do NOT execute "secrackit.py" without prior WRITTEN authorization from the owners of ANY target(s), system(s), and/or network(s) secrackit.py may run against.
 3. Do NOT use "secrackit.py" for illegal activities and/or purposes.
