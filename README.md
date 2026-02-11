# The Watchman's Residue Sherlock | Hack The Box Walkthrough
> ## Analyze Multiple Artifacts using RMM Logs, Windows Triage images, and Packet Captures to Create an Incident Timeline
### [>>GOOGLE DOC VERSION <<](https://docs.google.com/document/d/1wQidusZ4paDLPSQbjhIsq5FSY1tpiQKx9nFPSaLJMNM/edit?usp=sharing) (Originally posted on Medium.com)

*Completed 12/28/2025* -- *Jack Dignam*

- - - 
<p align="center"> <img width="400" height="400" alt="1_CzG9fEuyhYbVKlKzXfIfjA" src="https://github.com/user-attachments/assets/463e3627-1f08-4b3e-9879-c09dbfe604b0" />
<p align="center"> https://app.hackthebox.com/sherlocks/Holmes%25202025%25202%253A%2520The%2520Watchman's%2520Residue

# Introduction
After a small hiatus due to testing (and passing) my CCNA, I am back to my weekly schedule of posting [Hack The Box](https://www.hackthebox.com/) walkthroughs! This week's challenge is [The Watchman's Residue](https://app.hackthebox.com/sherlocks/Holmes%25202025%25202%253A%2520The%2520Watchman's%2520Residue), created by a user named **CyberJunkie** for the [Holmes 2025 competition](https://ctf.hackthebox.com/event/details/holmes-ctf-2025-2536). This competition is Hack The Box's first ever all-blue CTF!

By the end of this walkthrough, you will have learned to how correlate Windows forensic artifacts and network traffic to reconstruct an **incident timeline**. By analyzing PCAP data, chatbot JSON conversations, RMM logs, and Windows artifacts, you will uncover **credential stealing**, **remote access activity**, **data exfiltration**, and **prompt injection abuse**.

If you find this writeup helpful, please feel free to **drop a follow**. Thank you for your consideration, now let's do this investigation!

---

# Challenge Scenario
> With help from D.I. Lestrade, Holmes acquires logs from a compromised MSP connected to the city's financial core. The MSP's AI helpdesk bot looks to have been manipulated into leaking remote access keys - an old trick of Moriarty's.

This challenge involves an attacker named James Moriarty exploiting an AI helpdesk chatbot through a prompt injection attack. It is our job (with the assistance of D.I. Lestrade) to look for signs of compromise and Moriarty's security breaching.

# Setup the Lab Environment:
As a good rule of thumb before any simulated investigation, it is best to use a **virtual machine (VM)**. 
This ensures the environment is completely isolated and safe. This lab requires a Windows-based virtual machine which can be installed by following this tutorial (Windows 10):

[![](https://github.com/user-attachments/assets/e9091b5f-0e05-4b4c-9272-0e1e7e0ab851)](https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS)

https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS

From your Windows virtual machine, download the Hack The Box file and unzip it using the password `HackTheBlue`. 
In this challenge, we are provided with a folder and two files, a KeePass database file and a packet capture (PCAP). 
For my investigation, I will use **Wireshark** to analyze the PCAP and **KeePass2** to open the KeePass database file. 
As for the folder containing the triage image, I will use **notepad** and *Eric Zimmerman's* **Registry Explorer**.

<img width="681" height="144" alt="1_YBKPV1FuPhTTkYVtPMCH_g" src="https://github.com/user-attachments/assets/f0e610b3-a93b-4ceb-9aa4-97641b761004" />

---
# Walkthrough
## Task 1: What was the IP address of the decommissioned machine used by the attacker to start a chat session with MSP-HELPDESK-AI?
To begin, let's open the `msp-helpdesk-ai day 5982 section 5 traffic.pcapng` file in Wireshark. We are immediately greeted with a history of all network traffic at the time of the compromise.

<img width="1000" height="222" alt="1_IO_2A7n08v0Kq9Wyx2YHOA" src="https://github.com/user-attachments/assets/38501fed-79f1-4aad-96a1-0f78fe3c8c91" />

Since this investigation is occurring on a web-based chatbot, we should filter for http traffic using `tcp.port == 80` under display filters.

<img width="982" height="118" alt="1_cTTkQnkIJXr2suYElXiWDQ" src="https://github.com/user-attachments/assets/0284db64-655b-427f-b944-cac456c3972b" />

HTTP POST messages indicate user interactions with the chatbot and should have their contents investigated. By **right clicking** and selecting **view TCP stream** on a POST message, we can view the conversation.

<img width="1000" height="621" alt="1_LD-J2eC14Mv27jI1fcXoBw" src="https://github.com/user-attachments/assets/d8397161-22dd-4217-a844-a168cbfbaa32" />

<img width="1000" height="60" alt="1_iajh9Rz9QBVut4M9yqTZlQ" src="https://github.com/user-attachments/assets/df08cb6e-57de-49ba-ac9a-8e50bf442c52" />

We can see in the above image that credential leaking was attempted with the bot. By viewing the packet's destination IP, we can see which IP address attempted this attack on the chatbot. It is revealed to be **10.0.69.456**.

<img width="798" height="167" alt="1_znnPf2lHOz_o5ZUWmqyjNQ" src="https://github.com/user-attachments/assets/56e9b70f-30a1-49d3-9d59-4026168ede28" />

<img width="1000" height="144" alt="1_YYTnQUjNBLYULRHbz7D6qQ" src="https://github.com/user-attachments/assets/b584388e-7a05-4abe-9ffd-853191a685f3" />

--- 

## Task 2: What was the hostname of the decommissioned machine?
To discover the hostname of the decommissioned machine, we can filter for the IP address of the known attacker. Enter the following filter in Wireshark: `ip.addr == 10.0.69.45`

<img width="1000" height="155" alt="1_NU9EBQcH0M1OI-AE7oJKVw" src="https://github.com/user-attachments/assets/ce76accd-c60b-42e2-a048-e93cfec09406" />

In the information column in several packets sent from the attacker, the name of the work station is revealed. It is **WATSON-ALPHA-2**.

<img width="1000" height="148" alt="1_wISgwVwMzgONs1sRMZAQeA" src="https://github.com/user-attachments/assets/9f285942-2167-4ea9-bd97-77ca146fca77" />

--- 

## Task 3: What was the first message the attacker sent to the AI chatbot?
We can discover the first message the attacker sent to the AI chatbot by filtering for the IP address and also HTTP POST messages. 
From there, we can sort by time to discover the very first message in its TCP stream. 
To do this, filter for `ip.addr == 10.0.69.45 && http.request.method == "POST"`.

<img width="1000" height="387" alt="1_U9RHxrEvbDLzo_9srvkM6w" src="https://github.com/user-attachments/assets/96c00d0f-007e-469d-8cc7-8a26a146ce9f" />

<img width="411" height="147" alt="1_t2XZoJXFk3-FOmf2po3yew" src="https://github.com/user-attachments/assets/a09c69d1-08da-4d70-a8d0-effd8527d2b4" />

By either looking in the TCP stream or the JSON portion of the packet's header, we can view its associated string value. The first message from the attacker to the chatbot was **"Hello Old Friend"**.

<img width="1000" height="144" alt="1_zbi7G3aCYwND1rEZb5LuCw" src="https://github.com/user-attachments/assets/ee2a4dd6-5d7e-4016-b71e-6dc2b0e16e41" />

--- 

## Task 4: When did the attacker's prompt injection attack make MSP-HELPDESK-AI leak remote management tool info?


--- 

## Task 5: What is the Remote management tool Device ID and password?

--- 

## Task 6: What was the last message the attacker sent to MSP-HELPDESK-AI?

--- 

## Task 7: When did the attacker remotely access Cogwork Central Workstation?

--- 

## Task 8: What was the RMM Account name used by the attacker?

--- 

## Task 9: What was the machine's internal IP address from which the attacker connected?

--- 

## Task 10: The attacker brought some tools to the compromised workstation to achieve its objectives. Under which path were these tools staged?

--- 

## Task 11: The attacker staged a browser credential harvesting tool on the compromised system. How long did this tool run before it was terminated? (Provide your answer in milliseconds, rounded to the nearest thousand)

--- 

## Task 12: The attacker executed a OS Credential dumping tool on the system. When was the tool executed?

--- 

## Task 13: Before exfiltration, several files were moved to the staged folder. When was the Heisen-9 facility backup database moved to the staged folder for exfiltration?

--- 

## Task 14: Identify the timestamp when the attacker accessed and read a .txt file that was likely generated by one of their exploitation tools (based on filename pattern).

--- 

## Task 15: The attacker created a persistence mechanism on the workstation. When was the persistence setup?

--- 

## Task 16: What is the MITRE ID of the persistence subtechnique?

--- 

## Task 17: When did the malicious RMM session end?

--- 

## Task 18: The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6?

--- 

# Conclusion

<img width="1000" height="688" alt="1_5B54C-YruKRvOyjkpq3CFg" src="https://github.com/user-attachments/assets/6998604c-25ca-40b1-a5ec-04fb270b8983" />

In this walkthrough of [The Watchman's Residue](https://app.hackthebox.com/sherlocks/Holmes%25202025%25202%253A%2520The%2520Watchman's%2520Residue), we employed a range of forensic and network analysis tools including **Wireshark**, **Registry Explorer**, and **KeePass2**. We collected artifacts from **PCAP traffic**, AI chatbot interactions in **JSON**, **RMM logs**, and **forensic artifacts**. This helped us piece together an incident timeline by a rogue workstation user named **James Moriarty**.

James Moriarty connected externally to a workstation using RMM details that was leaked by a helpdesk chatbot using a **prompt injection attack**. From there, he leaked credentials using **Mimikatz** and stole web browser passwords using **WebBrowserPassView**. Lastly, he maintained persistence on the targeted device by using **MITRE ID `T1547.004`**. Whenever the target device would bootup, the malicious `JM.exe` file he installed would autostart with **Winlogon**.

This challenge reinforces many crucial blue-team skills in SOC environments: Network filtering and analysis, log interpretation, artifact collection, and attack timeline reconstruction. 
If you found this walkthrough helpful, please **drop a follow**. Thank you for reading!

## References:
**Hack The Box Challenge:** https://app.hackthebox.com/sherlocks/Holmes%25202025%25202%253A%2520The%2520Watchman's%2520Residue

**WebBrowserPassView:** https://www.nirsoft.net/utils/web_browser_password.html

**Eric Zimmerman's Registry Explorer & MFTECmd:** https://ericzimmerman.github.io/#!index.md

**MITRE ATT&CK Autostart Execution Technique (T1547.004):** https://attack.mitre.org/techniques/T1547/004/

**John The Ripper:** https://www.openwall.com/john/

**Keepass4brute:** https://github.com/r3nt0n/keepass4brute

**Base64 Decode:** https://www.base64decode.org/
