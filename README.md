# secrackit.py
**secrackit.py** automates the following in a single command:
- Windows auth checks (CrackMapExec)
- Dumps and parses secrets (Impacket-secretsdump)
- Cracks NTLM hashes (Hashcat)
---
#### Example syntax:
`./secrackit.py DC-IP domain.name IPs.txt accountname pw Password -localauth -out_dir ~/Desktop/toolsoutput -wordlist ~/Desktop/wordlists/customwordlist.txt -rule ~/media/hashcatrules/TwoRule.rule`

###### Arguments with a '-' (hyphen) are optional. Run `-h` for details.

#### Script requirements?
###### Crackmapexec, impacket-secretsdump, and hashcat need to be in your $PATH.
###### If you aren't specifying a wordlist, `/usr/share/wordlists/rockyou.txt` needs to be present.
###### If you're on Kali, you can extract rockyou.txt and then install the needed tools via apt.

---

#### 1. Story behind the script?
###### - After some AD labs online and at home, I found myself running these three scripts over and over. I also wanted to organize dumped hashes by prepending IP, SAM or NTDS, etc to the NTLM hashes.

#### 2. Why so many comments? XD
###### - I'm learning and it helps when I come back to it later. Maybe it'll help others too. :)

---

#### Shout-out to the makers of the tools "secrackit.py" simply automates:
##### 1. CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
##### 2. Impacket-secretsdump - https://github.com/fortra/impacket
##### 3. Hashcat - https://github.com/hashcat/hashcat

---

#### DISCLAIMER as of 1-23-24

##### 1. I take zero(0) responsibility for your actions if and when you ever use(execute) "secrackit.py".

##### 2. Do NOT execute "secrackit.py" without prior WRITTEN authorization from the owners of ANY target(s), system(s), and/or network(s) secrackit.py may run against.

##### 3. Do NOT use "secrackit.py" for illegal activities and/or purposes.
