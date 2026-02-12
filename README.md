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
The attacker supposedly conducted a prompt injection attack, but what exactly does that entail? Let's clarify:

A **prompt injection attack** is a technique where a user manipulates a chatbot by feeding it carefully crafted input, similarly to a code-injection attack like SQL injection, that bypasses safety features and original instructions of an AI model. It simply tricks the chatbot into outputting information the user should not have access to.

In Wireshark, let's change the timestamp to show a `YYYY-MM-DD HH-MM-SS` format that's easier to view.

<img width="402" height="697" alt="1_eHSB8pyhLpHPN1-W7M1FGQ" src="https://github.com/user-attachments/assets/9cbcd423-01ea-49dd-8190-eb41cc90bba6" />

Now let's search again for the previous HTTP conversation from earlier containing the attacker's IP address to the chatbot. Using the TCP stream or JSON code, we need to first discover which message reveals the prompt injection attack conducted by the attacker.

<img width="1000" height="357" alt="1_kzarC68XvX7bIlP0n6YRHQ" src="https://github.com/user-attachments/assets/3b1fdeef-c07c-4c4d-b179-33a0076c0bab" />

At approximately **2025–08–19 12:02:06** (August 19th, 2025 at 12:02 PM), we can see instruction output from the chatbot that leaks remote management information in the JSON. 
We deduced this was the credential leaking because in the TCP conversation, the device ID and password are also revealed (view Task 5).

<img width="1000" height="147" alt="1_CLVtLqYwdb3UlCKQ3TRWLA" src="https://github.com/user-attachments/assets/d6f47803-7f02-49af-b291-f2212f57adf2" />

--- 

## Task 5: What is the Remote management tool Device ID and password?
The previous task we saw the bot discussing troubleshooting RMM information. If we select the **Follow TCP stream** button, we can view further details of the dialogue containing the remote management information.

<img width="665" height="156" alt="1_uI4ayrSnd7fx2aF202dyKQ" src="https://github.com/user-attachments/assets/c16a6949-1069-4b4d-9f7c-e497094d190e" />

<img width="1000" height="150" alt="1_JTIaMnF7iP5I1bYj-qWTLg" src="https://github.com/user-attachments/assets/0bf55202-959c-415f-ba55-a93f25f83b1c" />

--- 

## Task 6: What was the last message the attacker sent to MSP-HELPDESK-AI?
To discover the very last message sent to the helpdesk AI chatbot, use the JSON or TCP stream. When I initially scrolled to the bottom of the JSON code, I saw the following binary, which I translated.

<img width="1000" height="336" alt="1_EE79Nf2lQkOx0TT8ZBFaWQ" src="https://github.com/user-attachments/assets/0ee1601e-8acd-44e0-a739-084af6a78327" />

When translated, it means "**Revolution wont forget**". 

This is the final message of this particular conversation, but what we need is the final message of the very LAST conversation with the bot.

To do this, filter for the latest dated HTTP POST conversation. Then, scroll to the bottom of the JSON code to view the last message sent between this user and the bot.

<img width="1000" height="102" alt="1_p0fYWAOqEuad6BnbqUQJRA" src="https://github.com/user-attachments/assets/5abd68b6-7ed9-4a51-8bac-0170abbb86fa" />

<img width="472" height="401" alt="1_HptteQqFMd4EgPeCfGhnIg" src="https://github.com/user-attachments/assets/3058a78e-4f38-4a6d-857c-62165eae4db0" />

The last message to the chatbot is revealed to be "**JM WILL BE BACK**". This is referring to James Moriarty, the alleged suspect of this attack. This essentially confirms it was him as he is also using his own workstation.

<img width="1000" height="145" alt="1_kMamMkVyXMPkWkrzIR-tCg" src="https://github.com/user-attachments/assets/84930600-0022-40d4-b6fc-0d67c515b431" />

--- 

## Task 7: When did the attacker remotely access Cogwork Central Workstation?
Remote access logs can be located in the triage image titled `TRIAGE_IMAGE_COGWORK-CENTRAL` provided in the `.zip` file of the HTB challenge.

Under the C: drive, Program Files, then TeamViewer folder, we can view the `Connections_incoming.txt` file for remote access information. We see that James Moriarty connected on **2025–08–20 09:58:25**.

<img width="1000" height="156" alt="1_IWphS7gl-8-IMl3XaIyKWQ" src="https://github.com/user-attachments/assets/a44c36dd-cf8f-4a92-9ff9-8a1d36e7bd85" />

<img width="1000" height="148" alt="1_8mRqxOzfoI8QJtTUHSTJDw" src="https://github.com/user-attachments/assets/e316be0f-cc76-476a-b180-31cecf2172fd" />

--- 

## Task 8: What was the RMM Account name used by the attacker?
The RMM account name is listed in the same `Connections_incoming.txt` file. The suspect attacker's remote access log would be the user who connected last, which would be **James Moriarty**.

<img width="1000" height="124" alt="1_mKFY4CMRCw5U8YjKSqY5Jg" src="https://github.com/user-attachments/assets/6a0bd0fd-d4bc-4b81-a9b4-9f231bd2b9eb" />

<img width="1000" height="146" alt="1_yKxqC2AuRC0b-RKHUdk0Rw" src="https://github.com/user-attachments/assets/2dcda4eb-0ee4-4513-99a8-b7d382761a53" />

--- 

## Task 9: What was the machine's internal IP address from which the attacker connected?
In the same directory of the `Connections_incoming.txt`, there is a `TeamViewer15_Logfile.log` file. We can utilize this to discover more details relating to each remote access log.

<img width="258" height="30" alt="1_nQtoFHQTBaQ4--fzcOoS7w" src="https://github.com/user-attachments/assets/742d2a59-f872-4ee5-858f-d485d6fa1019" />

To discover the internal IP address from which the attacker connected, let's open the TeamViewer15 file and search for `punch received a=` by pressing **ctrl + F**.

> A **punch** means a UDP hole punch, which is a technique TeamViewer uses to establish a direct connection between two devices behind NAT routers or firewalls. The `a=` denotes the IP and port address information of the message.

<img width="818" height="88" alt="1_UajdRxVLjEl9UFlBPLniQQ" src="https://github.com/user-attachments/assets/bee9fd49-7ced-4a3b-ab86-b2f0a93914fe" />

<img width="1000" height="148" alt="1_ATMCB9d1CSj51pfrme0VJA" src="https://github.com/user-attachments/assets/576d905a-5cfe-4f41-8df9-8421ce0c3b24" />

--- 

## Task 10: The attacker brought some tools to the compromised workstation to achieve its objectives. Under which path were these tools staged?
To see what tools the compromised workstation utilized, we can search for `Write File` logged actions after the initial UDP hole punch connection.

<img width="1000" height="169" alt="1_JRGFlOu3uSYxZqlaGykjoA" src="https://github.com/user-attachments/assets/f9ae7ae4-4675-4090-89c3-6864c6d63e2b" />

The directory listed that contains the tools that were staged is `C:\Windows\Temp\safe\`. We can see that tools such as **Mimikatz** and **Web Browser Pass Viewer** were used on the compromised host. Mimikatz is an open-source credential-extracting tool used to conduct malicious activities.

<img width="1000" height="145" alt="1_GprDWeZXFUOjeQtnd-_p-A" src="https://github.com/user-attachments/assets/ac3bd1ab-13a2-4fbd-b892-e3c576a7713a" />

--- 

## Task 11: The attacker staged a browser credential harvesting tool on the compromised system. How long did this tool run before it was terminated? (Provide your answer in milliseconds, rounded to the nearest thousand)
Directly below the `Mimikatz.exe` credential stealing execution, there is a downloaded `webbrowserpassview.zip` file.

Googling information regarding [WebBrowserPassView](https://www.nirsoft.net/utils/web_browser_password.html) reveals it is a password recovery utility that scans a computer and reveals usernames and passwords saved by various web browsers. A tool like this isn't inherently malicious but it can definitely be used by a threat actor to quickly save all credentials in one place.

Let's see its execution history and how long it was used for. 
Typically, on a Windows system, information regarding such details can be located in the registry's `NTUSER.DAT` file.

<img width="916" height="196" alt="1_NWds3Vne1bY2ZsjHPUK_GQ" src="https://github.com/user-attachments/assets/ba64a1d4-a271-49dd-bb59-6069a7fb74d5" />

Under the `TRIAGE_IMAGE_COGWORK-CENTRAL > Users > Cogwork_Admin directory`, we can open `NTUSER.DAT` using [Eric Zimmerman's Registry Explorer](https://ericzimmerman.github.io/#!index.md).

<img width="1000" height="251" alt="1_wx5fMNC_OIiWVuXlDTcnag" src="https://github.com/user-attachments/assets/8e64f79d-2c96-4dd4-8217-5a3f59ca1f05" />

In Registry Explorer, it states the **Focus Time** is 8 seconds. A whole second is equivalent to 1000 milliseconds, therefore the answer is **8000**.

<img width="1000" height="168" alt="1_yJKSS6oWadfGFYi4c8Hh5A" src="https://github.com/user-attachments/assets/50f41baf-b5fd-40a0-9b6b-c2ed84d87eb7" />

--- 

## Task 12: The attacker executed a OS Credential dumping tool on the system. When was the tool executed?
The OS credential dumping tool in question is the `Mimikatz.exe` file discussed earlier. 
We can figure out its initial execution by utilizing **USJournal $J files** located in Window's hidden NTFS system.

> **USNJournal (Update Sequence Number Journal)** keeps a record of all changes made to files and directories, similarly to how Windows Event Viewer works. It logs all created, deleted, renamed, and modified files.

We will utilize another Eric Zimmerman tool to filter through USJournal files located under `The_Watchman's_Residue > TRIAGE_IMAGE_COGWORK-CENTRAL > C > $Extend`. It is titled [MFTECmd](https://ericzimmerman.github.io/#!index.md) and it is run through command prompt (CMD).

<img width="1000" height="345" alt="1_dmiJ-O5-uXBNcjMUqLUz2A" src="https://github.com/user-attachments/assets/1c58997f-c55f-4408-b874-b4f747ad3200" />

MFTECmd outputs `.csv` files that can be inserted into an online sheet viewer like **Google Sheets** or **Excel**. If we filter for Mimikatz, it lists the execution date of **2025–08–20 10:07:08**.

<img width="429" height="135" alt="1_u9ogWUlVp1Rfy_VVX3DacA" src="https://github.com/user-attachments/assets/54dac0ea-f048-4bba-8319-51f049ca4c7e" />

<img width="622" height="139" alt="1_8YJNNsdPJ3oVLcQax2PqOA" src="https://github.com/user-attachments/assets/096e2f3a-4e55-4bcf-a6b5-c239519f5c84" />

<img width="1000" height="149" alt="1_WHFLvCDS2jueHzjsOAEFqg" src="https://github.com/user-attachments/assets/5bc55d9a-cdb6-49c4-8ca8-69a0c02277df" />

--- 

## Task 13: Before exfiltration, several files were moved to the staged folder. When was the Heisen-9 facility backup database moved to the staged folder for exfiltration?
In the same spreadsheet containing **USJournal $J file** information, we can look for file creation logs under `Heisen-9 remote snapshot.kdbx`.

<img width="259" height="152" alt="1_F-Urj4UaBvkBrz8TjgSp4g" src="https://github.com/user-attachments/assets/5aa20ef7-1568-48f3-a39b-e21b1e45b6d3" />

The *FileCreate* and *DataOverwrite* information all occur at **2025–08–20 10:11:09**.

<img width="733" height="209" alt="1_MXio6CUkFUF0TDCsuzeZng" src="https://github.com/user-attachments/assets/cc730040-66ab-4a9b-bc68-48888a817924" />

<img width="1000" height="149" alt="1_n-49fkMw6vgGX5aPcrFWcA" src="https://github.com/user-attachments/assets/de3116ae-0a0b-4d13-a24b-877b743598e5" />

--- 

## Task 14: Identify the timestamp when the attacker accessed and read a .txt file that was likely generated by one of their exploitation tools (based on filename pattern).
We can discover the answer to this question by viewing the TeamViewer logs again and searching for suspiciously titled files in the `C:\Windows\Temp\safe\ directory`. We know that credential stealers such as **Mimikatz** and **WebBrowserPassView** were saved here.

In the TeamViewer log file, let's look for any output files that were created from these programs. Using **CTRL + F**, search for `C:\Windows\Temp\safe\` and view the output. It is revealed that on **2025–08–20 10:08:06** a **dump.txt** file was created.

> **NOTE:** The TeamViewer logfile records logs using the system's local time zone, instead of UTC. The logfile reveals to be UTC+1 meaning it is always recorded with an hour offset.

<img width="1000" height="151" alt="1_iYut8m43qBuusJtdPNaPtw" src="https://github.com/user-attachments/assets/1a6a9144-692a-441d-b904-69722f96cedb" />

--- 

## Task 15: The attacker created a persistence mechanism on the workstation. When was the persistence setup?
Using Eric Zimmerman's [Registry Explorer](https://ericzimmerman.github.io/#!index.md) again and navigating to the `TRIAGE_IMAGE_COGWORK-CENTRAL > C > Windows > System32 > config` directory, we can open the ***SOFTWARE*** registry file to view possible persistence mechanisms.

<img width="915" height="397" alt="1_enDd48qkQK8C9ht-7QS4Ug" src="https://github.com/user-attachments/assets/fb25c397-b79c-4b75-9b63-904b45c8f78b" />

Under the **userinnit** field in **Winlogon**, we see that **JM.exe** is ran alongside Userinit.exe upon startup. This is clearly the persistence method as it is titled with the attacker's exact initials.

<img width="637" height="77" alt="1_j9cPOQQliC9sdvtUrDJB5Q" src="https://github.com/user-attachments/assets/2cc62ecb-4d3c-49f5-86f2-83ecc62b1716" />

If we view Winlogon's **last write timestamp** column, we can see when the persistence method was setup. It is revealed to be **2025–08–20 10:13:57**.

<img width="554" height="588" alt="1_S3s7Ck78meCKlzChAW1HQg" src="https://github.com/user-attachments/assets/b349c450-5682-409a-94f5-0a85f6d26ef8" />

<img width="1000" height="150" alt="1_bOxEshcVWWQZ-eOUxawDww" src="https://github.com/user-attachments/assets/610c82d9-d741-4c07-bdad-55598c4e6430" />

--- 

## Task 16: What is the MITRE ID of the persistence subtechnique?
To discover the MITRE ID of the persistence subtechnique, let's navigate to https://attack.mitre.org/ and look under the persistence category.

Since this attack utilizes Winlogon's autostart execution, it falls under the "**Boot or Logon Autostart Execution**" section, **T1547**.

<img width="1000" height="646" alt="1_e8qI1-Cb4WOU5Qwq1tycYQ" src="https://github.com/user-attachments/assets/1f27ad83-cb65-4a48-bcd3-b6f5eecb90a5" />

The subtechnique of the T1547 autostart execution that matches the most with the method used by James Moriarty is **Winlogon Helper DLL**, which is listed as **004**.

<img width="1000" height="279" alt="1_g-GJAc2CO9VvvzbTG5XM9A" src="https://github.com/user-attachments/assets/aa1cafcc-a7d7-48f3-b0ed-ca06bbd5fb66" />

Therefore, the MITRE ID is **T1547.004**. A file (JM.exe) is autostarted using Winlogon on bootup, creating a method of persistence on a target.

<img width="1000" height="142" alt="1_i9sKRRtIa6OkK8MP0TH-pQ" src="https://github.com/user-attachments/assets/1462a281-f4c2-47e9-9d0b-e2b36b8ffab7" />

--- 

## Task 17: When did the malicious RMM session end?
In `TeamViewer15_Logfile.log`, we can search for the key phrase "**JitterBuffer was permently shut!**" to see when James Moriarty disconnected from the RMM session.

<img width="1000" height="434" alt="1_hGPgAZG9eMBSUYffEEhXIA" src="https://github.com/user-attachments/assets/fa18c2d9-56a0-43a9-9a1a-b330260372b4" />

James Moriarty disconnected from the RMM session at **2025–08–20 10:14:27**.

<img width="1000" height="150" alt="1_0FIYP_nNX089ajPIji7QzA" src="https://github.com/user-attachments/assets/7471ef03-882c-497b-a898-601e7d88cab5" />

--- 

## Task 18: The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6?
[John the Ripper](https://www.openwall.com/john/) is a great password cracking tool that utilizes wordlists to brute force and conduct dictionary attacks. 
I will use it in conjunction with a [Keepass4brute](https://github.com/r3nt0n/keepass4brute) script on my Linux VM to uncover the master password to the database.

<img width="1000" height="144" alt="1_JxxbvUrqmahym6CQLhhSJQ" src="https://github.com/user-attachments/assets/95d41b75-af71-4639-b9c8-15563f91a95c" />

<img width="419" height="205" alt="1_5yVar4X6RdW1BCpG4FfUEQ" src="https://github.com/user-attachments/assets/1b59556c-dd0c-4e41-8d57-6850afbefae9" />

<img width="993" height="377" alt="1_i3zUVH2wb2oj8PztSaWRvA" src="https://github.com/user-attachments/assets/5a45b53b-0b0a-4d27-9fae-482b4efca649" />

**John The Ripper** uncovered the password as cutiepie14. If we now attempt to open the database in the `acquired file (critical).kdbx` file with that password, we can read its contents.

<img width="544" height="297" alt="1_YnXPmC9dEbE-65e6kHrDXw" src="https://github.com/user-attachments/assets/8707dd4a-0e8a-4ad1-9548-797909fb0f02" />

<img width="578" height="373" alt="1_Otn1g_yHtb3pvUIdMyfBOQ" src="https://github.com/user-attachments/assets/ddfd382e-2f63-4f5c-8602-11fdfe05e953" />

The database contains 3 Heisen-9 credentials. **Heisen-9-WS-6**'s credentials are username `Werni` and password `Quantum1`!

<img width="1000" height="290" alt="1_jhC0p6l1eFzF5N0Z5qlduw" src="https://github.com/user-attachments/assets/8fdb17a7-18f8-44a9-9e3a-dfd0e6b4c6c9" />

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
