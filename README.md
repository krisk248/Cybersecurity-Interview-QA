# Security Interview Study Notes


### Contents
- [README](README.md)
- [Learning Tips](#learning-tips)
- [Interviewing Tips](#interviewing-tips)
- [Networking](#networking)
- [Web Application](#web-application)
- [Infrastructure (Prod / Cloud) Virtualisation](#infrastructure-prod--cloud-virtualisation)
- [OS Implementation and Systems](#os-implementation-and-systems)
- [Mitigations](#mitigations)
- [Cryptography, Authentication, Identity](#cryptography-authentication-identity)
- [Malware & Reversing](#malware--reversing)
- [Exploits](#exploits)
- [Attack Structure](#attack-structure)
- [Threat Modeling](#threat-modeling)
- [Detection](#detection)
- [Digital Forensics](#digital-forensics)
- [Incident Management](#incident-management)
- [Coding & Algorithms](#coding--algorithms)
- [Security Themed Coding Challenges](#security-themed-coding-challenges)
- [Cyber_Security_Interview_Questions](#cyber_security_interview_questions)


# Cyber Secuirty Job Roles

![image](./Cyber_Security_Job_Roles.png)

# To-Do
- [ ] Add answers to questions
- [ ] Categorize the questions and answers
- [ ] Add cheatsheet and images
- [ ] Add books and categorize the basic data

# Learning Tips 

- [Summary on how to learn](https://medium.com/learn-love-code/learnings-from-learning-how-to-learn-19d149920dc4) on Medium.

- **Track concepts - "To learn", "Revising", "Done"**
	- Any terms I couldn't easily explain went on to post-its. 
	- One term per post-it. 
	- "To learn", "Revising", "Done" was written on my whiteboard and I moved my post-its between these categories, I attended to this every few days.
	- I looked up terms everyday, and I practiced recalling terms and explaining them to myself every time I remembered I had these interviews coming up (frequently).
	- I focused on the most difficult topics first before moving onto easier topics.
	- I carried around a notebook and wrote down terms and explanations. 
	- Using paper reduces distractions.

- **How to review concepts**
	- Use spaced-repetition.
	- Don't immediately look up the answer, EVEN IF you have never seen the term before. Ask yourself what the term means. Guess the answer. Then look it up.
	- Review terms *all the time*. You can review items in your head at any time. If I was struggling to fall asleep, I'd go through terms in my head and explained them to myself. 100% success rate of falling asleep in less than 10 minutes, works every time. 

- **Target your learning**
	- Think *hard* about what specific team you are going for, what skills do they want? If you aren't sure, then ask someone who will definitely know.
	- Always focus on the areas you struggle with the most *first* in a study session. Then move on to easier or more familiar topics. 

- **Identify what you need to work on** 
	- Spend more time doing the difficult things.
	- If you're weak on coding and you find yourself avoiding it, then spend most of your study time doing that.

- **Read**
	- Read relevant books (you don't have to read back to back).
	- When looking up things online, avoid going more than two referral links deep - this will save you from browser tab hell.

- **Mental health**
	- Take care of your basic needs first - sleep, eat well, drink water, gentle exercise. You know yourself, so do what's best for you.
	- You are more than your economic output, remember to separate your self worth from your paycheque. 
	- See interviews for what they are - they are *not* a measure of you being "good enough".


# Interviewing Tips 

- **Interview questions**
	- Interview questions are intentionally vague. This is to encourage questions.
	- Ask clarifying questions 
	- Questions reveal how you approach problems.
	- Write down notes about the question. This is so you don't forget details and only partially answer, or give the wrong answer.
	- Interviews should be more like a conversation with a lot of back and forth, thoroughly explore scenarios together and avoid jumping too fast to a solution.
	- The interviewer can only make an evaluation on your suitability for the job based on the things you *say*. 
	- **Interviewers test depth of knowledge**
		- There will be questions about technical details on topics to the point where it'll be hard to answer. This is okay, try your best to work through it and say what you're thinking.
		- Interviewers often aren't looking for specific answers, they just want to see how deeply you know a topic.
		- Approach the question from a low level and even ask your interviewer if you need to add more details before moving on.
	- **Interviewers test breadth of knowledge**
		- There will be questions related to the role you're applying for and some that aren't. This is to explore breadth of knowledge. 
		- Try your best to explore the scenarios and ask questions. It's very important to say your thinking aloud, you might be on the right track.

- **Show comprehension**
	- Try to always ask clarifying questions even if you think you already know the answer. You might learn some nuance that even improves your idea.
	- Always repeat the question back to the interviewer to both check your understanding and give yourself thinking time.
	- *"Okay, I'll repeat back the question so I can check my understanding…"*
	- *"Just to clarify…"*
	- *"I just want to check I heard correctly…"*
	
- **State your assumptions**
	- Your interviewer will provide feedback if your assumptions are unreasonable.
	- *"I am going to assume that the organisation is collecting x,y,z logs from hosts and storing these for at least 90 days…"* 
	- *"Can I make the assumption that…?"*
	- *"Let's say that we can get x,y,z information…"*

- **When asked a question you're not sure of the answer to right away, try these phrases:**
	- *"I don't know but if I had to invent it, it would be like this…"*
	- *"I don't know that exactly but I know something about a similar subject / sub component…"*
	- *"This is what's popping into my mind right now is…"*
	- *"The only thing that is coming to mind is…"* 
	- *"I know a lot about [similar thing], I could talk about that instead? Would that be okay?"*

- **Say what you are thinking**
	- The interviewer can only make an evaluation on your suitability for the job based on the things you *say*. 
	- If you don't say your thought process aloud, then the interviewer doesn't know what you know. 
	- You may well be on the right track with an answer. You'll be kicking yourself afterwards if you later realise you were but didn't say anything (I missed out on an internship because of this!).
	- Write pseudo code for your coding solution so you don't have to hold everything in your head.
	- *"Right now I am thinking about…"*
	- *"I am thinking about different approaches, for example…"*
	- *"I keep coming back to [subject/idea/thing] but I think that's not the right direction. I am thinking about…"*
	- *"I'm interested in this idea that…"*

- **Reduce cognitive load**
	- Take notes on the question and assumptions during the interview.
	- If the infrastructure is complicated, draw up what you think it looks like. 
	- Write pseudocode. 
	- Write tests and expected output for code you write, test your code against it. 

- **Prepare**
	- Make a checklist that reminds you of what to do for each question, something like:
		- Listen to interview question
		- Take notes on the question
		- Repeat the question
		- Ask clarifying questions
		- State any assumptions
	- Prepare questions that you want to ask your interviewers at the end of the interview so you don't need to think of them on the spot on the day. Since an interview is also for you to know more about the workplace, I asked questions about the worst parts of the job. 
	- Bring some small snacks in a box or container that isn't noisy and distracting. A little bit of sugar throughout the interviews can help your problem solving abilities. 
	- Stay hydrated - and take a toilet break between every interview if you need to (it's good to take a quiet moment).

- **Do practice interviews**
	- Do them until they feel more comfortable and you can easily talk through problems.
	- Ask your friends/peers to give you really hard questions that you definitely don't know how to answer.
	- Practice being in the very uncomfortable position where you have no idea about the topic you've been asked. Work through it from first principles.
	- Practice speaking aloud everything you know about a topic, even details you think might be irrelevant. 
	- Doooo theeeeemmm yes they can be annoying to organise but it is *worth it*.

## Interviewers are potential friends and they want to help you get the job, they are on your side. Let them help you, ask them questions, recite everything you know on a topic and *say your thought process out loud*.

# Basic Concepts for CyberSecurity
----------------

# Networking 

- **OSI Model**
	- Application; layer 7 (and basically layers 5 & 6) (includes API, HTTP, etc).
	- Transport; layer 4 (TCP/UDP).
	- Network; layer 3 (Routing).
	- Datalink; layer 2 (Error checking and frame synchronisation).
	- Physical; layer 1 (Bits over fibre).	
- **Firewalls**
	- Rules to prevent incoming and outgoing connections.	
- **NAT** 
	- Useful to understand IPv4 vs IPv6.
- **DNS**
	- (53)
	- Requests to DNS are usually UDP, unless the server gives a redirect notice asking for a TCP connection. Look up in cache happens first. DNS exfiltration. Using raw IP addresses means no DNS logs, but there are HTTP logs. DNS sinkholes.
	- In a reverse DNS lookup, PTR might contain- 2.152.80.208.in-addr.arpa, which will map to  208.80.152.2. DNS lookups start at the end of the string and work backwards, which is why the IP address is backwards in PTR.
- **DNS** exfiltration 
	- Sending data as subdomains. 
	- 26856485f6476a567567c6576e678.badguy.com
	- Doesn’t show up in http logs. 
- **DNS** configs
	- Start of Authority (SOA).
	- IP addresses (A and AAAA).
	- SMTP mail exchangers (MX).
	- Name servers (NS).
	- Pointers for reverse DNS lookups (PTR).
	- Domain name aliases (CNAME).
- **ARP**
	- Pair MAC address with IP Address for IP connections. 
- **DHCP**
	- UDP (67 - Server, 68 - Client)
	- Dynamic address allocation (allocated by router).
	- `DHCPDISCOVER` -> `DHCPOFFER` -> `DHCPREQUEST` -> `DHCPACK`
- **Multiplex** 
	- Timeshare, statistical share, just useful to know it exists.
- **Traceroute** 
	- Usually uses UDP, but might also use ICMP Echo Request or TCP SYN. TTL, or hop-limit.
	- Initial hop-limit is 128 for windows and 64 for *nix. Destination returns ICMP Echo Reply. 
- **Nmap** 
	- Network scanning tool.
- **Intercepts** (PitM - Person in the middle)
	- Understand PKI (public key infrastructure in relation to this).
- **VPN** 
	- Hide traffic from ISP but expose traffic to VPN provider.
- **Tor** 
	- Traffic is obvious on a network. 
	- How do organised crime investigators find people on tor networks. 
- **Proxy**  
	- Why 7 proxies won’t help you. 
- **BGP**
	- Border Gateway Protocol.
	- Holds the internet together.
- **Network** traffic tools
	- Wireshark
	- Tcpdump
	- Burp suite
- **HTTP**/S 
	- (80, 443)
- **SSL**/TLS
	- (443) 
	- Super important to learn this, includes learning about handshakes, encryption, signing, certificate authorities, trust systems. A good [primer](https://english.ncsc.nl/publications/publications/2021/january/19/it-security-guidelines-for-transport-layer-security-2.1) on all these concepts and algorithms is made available by the Dutch cybersecurity center.
	- POODLE, BEAST, CRIME, BREACH, HEARTBLEED.
- **TCP**/UDP
	- Web traffic, chat, voip, traceroute.
	- TCP will throttle back if packets are lost but UDP doesn't. 
	- Streaming can slow network TCP connections sharing the same network.
- **ICMP** 
	- Ping and traceroute.
- **Mail**
	- SMTP (25, 587, 465)
	- IMAP (143, 993)
	- POP3 (110, 995)
- **SSH** 
	- (22)
	- Handshake uses asymmetric encryption to exchange symmetric key.
- **Telnet**
	- (23, 992)
	- Allows remote communication with hosts.
- **ARP**  
	- Who is 0.0.0.0? Tell 0.0.0.1.
	- Linking IP address to MAC, Looks at cache first.
- **DHCP** 
	- (67, 68) (546, 547)
	- Dynamic (leases IP address, not persistent).
	- Automatic (leases IP address and remembers MAC and IP pairing in a table).
	- Manual (static IP set by administrator).
- **IRC** 
	- Understand use by hackers (botnets).
- **FTP**/**SFTP** 
	- (21, 22)
- **RPC** 
	- Predefined set of tasks that remote clients can execute.
	- Used inside orgs. 
- **Service** ports
	- 0 - 1023: Reserved for common services - sudo required. 
	- 1024 - 49151: Registered ports used for IANA-registered services. 
	- 49152 - 65535: Dynamic ports that can be used for anything. 
- **HTTP Header**
	- | Verb | Path | HTTP version |
	- Domain
	- Accept
	- Accept-language
	- Accept-charset
	- Accept-encoding(compression type)
	- Connection- close or keep-alive
	- Referrer
	- Return address
	- Expected Size?
- **HTTP Response Header**
	- HTTP version
	- Status Codes: 
		- 1xx: Informational Response
		- 2xx: Successful
		- 3xx: Redirection
		- 4xx: Client Error
		- 5xx: Server Error
	- Type of data in response 
	- Type of encoding
	- Language 
	- Charset
- **UDP Header**
	- Source port
	- Destination port
	- Length
	- Checksum
-**Broadcast domains and collision domains.** 
- **Root stores**
- **CAM table overflow**


# Web Application 

- **Same origin policy**
	- Only accept requests from the same origin domain.  
- **CORS** 
	- Cross-Origin Resource Sharing. Can specify allowed origins in HTTP headers. Sends a preflight request with options set asking if the server approves, and if the server approves, then the actual request is sent (eg. should client send auth cookies).
- **HSTS** 
	- Policies, eg what websites use HTTPS.
- **Cert** **transparency** 
	- Can verify certificates against public logs 	
- **HTTP Public Key Pinning**
	- (HPKP)
	- Deprecated by Google Chrome
- **Cookies** 
	- httponly - cannot be accessed by javascript.
- **CSRF**
	- Cross-Site Request Forgery.
	- Cookies.
- **XSS**
	- Reflected XSS.
	- Persistent XSS.
	- DOM based /client-side XSS.
	- `<img scr=””>` will often load content from other websites, making a cross-origin HTTP request. 
- **SQLi** 
	- Person-in-the-browser (flash / java applets) (malware).
	- Validation / sanitisation of webforms.
- **POST** 
	- Form data. 
- **GET** 
	- Queries. 
	- Visible from URL.
- **Directory** **traversal** 
	- Find directories on the server you’re not meant to be able to see.
	- There are tools that do this.
- **APIs** 
	- Think about what information they return. 
	- And what can be sent.
- **Beefhook**
	- Get info about Chrome extensions.
- **User agents**
	- Is this a legitimate browser? Or a botnet?
- **Browser extension take-overs**
	- Miners, cred stealers, adware.
- **Local file inclusion**
- **Remote file inclusion (not as common these days)**
- **SSRF** 
	- Server Side Request Forgery.
- **Web vuln scanners. **
- **SQLmap.**
- **Malicious redirects.**


# Infrastructure (Prod / Cloud) Virtualisation 

- **Hypervisors**.
- **Hyperjacking**.
- **Containers, VMs, clusters.**
- **Escaping techniques.**
	- Network connections from VMs / containers.  
- **Lateral movement and privilege escalation techniques.**
	- Cloud Service Accounts can be used for lateral movement and privilege escalation in Cloud environments.
	- GCPloit tool for Google Cloud Projects.
- **Site isolation.**
- **Side-channel attacks.**
	- Spectre, Meltdown.
- **Beyondcorp** 
	- Trusting the host but not the network.
- **Log4j vuln. **


# OS Implementation and Systems

- Privilege escalation techniques, and prevention.
- Buffer Overflows.
- Directory traversal (prevention).
- Remote Code Execution / getting shells.
- Local databases
	- Some messaging apps use sqlite for storing messages.
	- Useful for digital forensics, especially on phones.
- Windows
	- Windows registry and group policy.
	- Active Directory (AD).
		- Bloodhound tool. 
		- Kerberos authentication with AD.
	- Windows SMB. 
	- Samba (with SMB).
	- Buffer Overflows. 
	- ROP. 
	
- *nix 
	- SELinux.
	- Kernel, userspace, permissions.
	- MAC vs DAC.
	- /proc
	- /tmp - code can be saved here and executed.
	- /shadow 
	- LDAP - Lightweight Directory Browsing Protocol. Lets users have one password for many services. This is similar to Active Directory in windows.
- MacOS
	- Gotofail error (SSL).
	- MacSweeper.
	- Research Mac vulnerabilities.

## Mitigations 
- Patching 
- Data Execution Prevention
- Address space layout randomisation
	- To make it harder for buffer overruns to execute privileged instructions at known addresses in memory.
- Principle of least privilege
	- Eg running Internet Explorer with the Administrator SID disabled in the process token. Reduces the ability of buffer overrun exploits to run as elevated user.
- Code signing
	- Requiring kernel mode code to be digitally signed.
- Compiler security features
	- Use of compilers that trap buffer overruns.
- Encryption
	- Of software and/or firmware components.
- Mandatory Access Controls
	- (MACs)
	- Access Control Lists (ACLs)
	- Operating systems with Mandatory Access Controls - eg. SELinux.
- "Insecure by exception"
	- When to allow people to do certain things for their job, and how to improve everything else. Don't try to "fix" security, just improve it by 99%.
- Do not blame the user
	- Security is about protecting people, we should build technology that people can trust, not constantly blame users. 


# Cryptography, Authentication, Identity 

- Encryption vs Encoding vs Hashing vs Obfuscation vs Signing
	- Be able to explain the differences between these things. 
	- [Various attack models](https://en.wikipedia.org/wiki/Attack_model) (e.g. chosen-plaintext attack).

- Encryption standards + implementations
	- [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) (asymmetrical).
	- [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (symmetrical).
	- [ECC](https://en.wikipedia.org/wiki/EdDSA) (namely ed25519) (asymmetric).
	- [Chacha/Salsa](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) (symmetric).

- Asymmetric vs symmetric
	- Asymmetric is slow, but good for establishing a trusted connection.
	- Symmetric has a shared key and is faster. Protocols often use asymmetric to transfer symmetric key.
	- Perfect forward secrecy - eg Signal uses this.

- Cyphers
	- Block vs stream [ciphers](https://en.wikipedia.org/wiki/Cipher).
	- [Block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).
	- [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).

- Integrity and authenticity primitives
	- [Hashing functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) e.g. MD5, Sha-1, BLAKE. Used for identifiers, very useful for fingerprinting malware samples.
	- [Message Authentication Codes (MACs)](https://en.wikipedia.org/wiki/Message_authentication_code).
	- [Keyed-hash MAC (HMAC)](https://en.wikipedia.org/wiki/HMAC).

- Entropy
	- PRNG (pseudo random number generators).
	- Entropy buffer draining.
	- Methods of filling entropy buffer.

- Authentication
	- Certificates 
		- What info do certs contain, how are they signed? 
		- Look at DigiNotar.
	- Trusted Platform Module 
		- (TPM)
		- Trusted storage for certs and auth data locally on device/host.
	- O-auth
		- Bearer tokens, this can be stolen and used, just like cookies.
	- Auth Cookies
		- Client side.
	- Sessions 
		- Server side.
	- Auth systems 
		- SAMLv2o.
		- OpenID.
		- Kerberos. 
			- Gold & silver tickets.
			- Mimikatz.
			- Pass-the-hash.	  
	- Biometrics
		- Can't rotate unlike passwords.
	- Password management
		- Rotating passwords (and why this is bad). 
		- Different password lockers. 
	- U2F / FIDO
		- Eg. Yubikeys.
		- Helps prevent successful phishing of credentials.
	- Compare and contrast multi-factor auth methods.

- Identity
	- Access Control Lists (ACLs)
		- Control which authenicated users can access which resources.
	- Service accounts vs User accounts
		- Robot accounts or Service accounts are used for automation.
		- Service accounts should have heavily restricted priviledges.
		- Understanding how Service accounts are used by attackers is important for understanding Cloud security.  
	- impersonation
		- Exported account keys.
		- ActAs, JWT (JSON Web Token) in Cloud.
	- Federated identity


# Malware & Reversing

- Interesting malware
	- Conficker.
	- Morris worm.
	- Zeus malware.
	- Stuxnet.
	- Wannacry.
	- CookieMiner.
	- Sunburst.

- Malware features
	- Various methods of getting remote code execution. 
	- Domain-flux.
	- Fast-Flux.
	- Covert C2 channels.
	- Evasion techniques (e.g. anti-sandbox).
	- Process hollowing. 
	- Mutexes.
	- Multi-vector and polymorphic attacks.
	- RAT (remote access trojan) features.

- Decompiling/ reversing 
	- Obfuscation of code, unique strings (you can use for identifying code).
	- IdaPro, Ghidra.

- Static / dynamic analysis
	- Describe the differences.
	- Virus total. 
	- Reverse.it. 
	- Hybrid Analysis.


# Exploits

- Three ways to attack - Social, Physical, Network 
	- **Social**
		- Ask the person for access, phishing. 
		- Cognitive biases - look at how these are exploited.
		- Spear phishing.
		- Water holing.
		- Baiting (dropping CDs or USB drivers and hoping people use them).
		- Tailgating.
	- **Physical** 
		- Get hard drive access, will it be encrypted? 
		- Boot from linux. 
		- Brute force password.
		- Keyloggers.
		- Frequency jamming (bluetooth/wifi).
		- Covert listening devices.
		- Hidden cameras.
		- Disk encryption. 
		- Trusted Platform Module.
		- Spying via unintentional radio or electrical signals, sounds, and vibrations (TEMPEST - NSA).
	- **Network** 
		- Nmap.
		- Find CVEs for any services running.
		- Interception attacks.
		- Getting unsecured info over the network.

- Exploit Kits and drive-by download attacks

- Remote Control
	- Remote code execution (RCE) and privilege.
	- Bind shell (opens port and waits for attacker).
	- Reverse shell (connects to port on attackers C2 server).

- Spoofing
	- Email spoofing.
	- IP address spoofing.
	- MAC spoofing.
	- Biometric spoofing.
	- ARP spoofing.

- Tools
	- Metasploit.
	- ExploitDB.
	- Shodan - Google but for devices/servers connected to the internet.
	- Google the version number of anything to look for exploits.
	- Hak5 tools.


# Attack Structure

Practice describing security concepts in the context of an attack. These categories are a rough guide on attack structure for a targeted attack. Non-targeted attacks tend to be a bit more "all-in-one".

- Reconnaissance
	- OSINT, Google dorking, Shodan.
- Resource development
	- Get infrastructure (via compromise or otherwise).
	- Build malware.
	- Compromise accounts.
- Initial access
	- Phishing.
	- Hardware placements.
	- Supply chain compromise.
	- Exploit public-facing apps.
- Execution
	- Shells & interpreters (powershell, python, javascript, etc.).
	- Scheduled tasks, Windows Management Instrumentation (WMI).
- Persistence
	- Additional accounts/creds.
	- Start-up/log-on/boot scripts, modify launch agents, DLL side-loading, Webshells.
	- Scheduled tasks.
- Privilege escalation
	- Sudo, token/key theft, IAM/group policy modification.
	- Many persistence exploits are PrivEsc methods too.
- Defense evasion
	- Disable detection software & logging.
	- Revert VM/Cloud instances.
	- Process hollowing/injection, bootkits.
- Credential access
	- Brute force, access password managers, keylogging.
	- etc/passwd & etc/shadow.
	- Windows DCSync, Kerberos Gold & Silver tickets.
	- Clear-text creds in files/pastebin, etc.
- Discovery
	- Network scanning.
	- Find accounts by listing policies.
	- Find remote systems, software and system info, VM/sandbox.
- Lateral movement
	- SSH/RDP/SMB.
	- Compromise shared content, internal spear phishing.
	- Pass the hash/ticket, tokens, cookies.
- Collection
	- Database dumps.
	- Audio/video/screen capture, keylogging.
	- Internal documentation, network shared drives, internal traffic interception.
- Exfiltration
	- Removable media/USB, Bluetooth exfil.
	- C2 channels, DNS exfil, web services like code repos & Cloud backup storage.
	- Scheduled transfers.
- Command and control
	- Web service (dead drop resolvers, one-way/bi-directional traffic), encrypted channels.
	- Removable media.
	- Steganography, encoded commands.
- Impact
	- Deleted accounts or data, encrypt data (like ransomware).
	- Defacement.
	- Denial of service, shutdown/reboot systems.


# Threat Modeling

- Threat Matrix
- Trust Boundries
- Security Controls
- STRIDE framework
	- **S**poofing
	- **T**ampering
	- **R**epudiation
	- **I**nformation disclosure
	- **D**enial of service
	- **E**levation of privilege 
- [MITRE Att&ck](https://attack.mitre.org/) framework
- [Excellent talk](https://www.youtube.com/watch?v=vbwb6zqjZ7o) on "Defense Against the Dark Arts" by Lilly Ryan (contains *many* Harry Potter spoilers)


# Detection

- IDS
	- Intrusion Detection System (signature based (eg. snort) or behaviour based).
	- Snort/Suricata/YARA rule writing
	- Host-based Intrusion Detection System (eg. OSSEC)

- SIEM
	- Security Information and Event Management.

- IOC 
	- Indicator of compromise (often shared amongst orgs/groups).
	- Specific details (e.g. IP addresses, hashes, domains)

- Things that create signals
	- Honeypots, snort.

- Things that triage signals
	- SIEM, eg splunk.

- Things that will alert a human 
	- Automatic triage of collated logs, machine learning.
	- Notifications and analyst fatigue.
	- Systems that make it easy to decide if alert is actual hacks or not.

- Signatures
	- Host-based signatures
		- Eg changes to the registry, files created or modified.
		- Strings in found in malware samples appearing in binaries installed on hosts (/Antivirus).
	- Network signatures
		- Eg checking DNS records for attempts to contact C2 (command and control) servers. 

- Anomaly / Behaviour based detection 
	- IDS learns model of “normal” behaviour, then can detect things that deviate too far from normal - eg unusual urls being accessed, user specific- login times / usual work hours, normal files accessed.  
	- Can also look for things that a hacker might specifically do (eg, HISTFILE commands, accessing /proc).
	- If someone is inside the network- If action could be suspicious, increase log verbosity for that user.

- Firewall rules
	- Brute force (trying to log in with a lot of failures).
	- Detecting port scanning (could look for TCP SYN packets with no following SYN ACK/ half connections).
	- Antivirus software notifications.
	- Large amounts of upload traffic.

- Honey pots
	- Canary tokens.
	- Dummy internal service / web server, can check traffic, see what attacker tries.

- Things to know about attackers
	- Slow attacks are harder to detect.
	- Attacker can spoof packets that look like other types of attacks, deliberately create a lot of noise.
	- Attacker can spoof IP address sending packets, but can check TTL of packets and TTL of reverse lookup to find spoofed addresses.
	- Correlating IPs with physical location (is difficult and inaccurate often).

- Logs to look at
	- DNS queries to suspicious domains.
	- HTTP headers could contain wonky information.
	- Metadata of files (eg. author of file) (more forensics?).
	- Traffic volume.
	- Traffic patterns.
	- Execution logs.

- Detection related tools
	- Splunk.
	- Arcsight.
	- Qradar.
	- Darktrace.
	- Tcpdump.
	- Wireshark.
	- Zeek.

- **A curated list of** [awesome threat detection](https://github.com/0x4D31/awesome-threat-detection) **resources**

# Digital Forensics

 - Evidence volatility (network vs memory vs disk)

 - Network forensics
	- DNS logs / passive DNS
	- Netflow
	- Sampling rate

 - Disk forensics
	- Disk imaging
	- Filesystems (NTFS / ext2/3/4 / AFPS)
	- Logs (Windows event logs, Unix system logs, application logs)
	- Data recovery (carving)
	- Tools
	- plaso / log2timeline
	- FTK imager
	- encase

 - Memory forensics
	- Memory acquisition (footprint, smear, hiberfiles)
	- Virtual vs physical memory
	- Life of an executable
	- Memory structures
	- Kernel space vs user space
	- Tools
	- Volatility
	- Google Rapid Response (GRR) / Rekall
	- WinDbg

  - Mobile forensics
	- Jailbreaking devices, implications
	- Differences between mobile and computer forensics
	- Android vs. iPhone

  - Anti forensics
	- How does malware try to hide?
	- Timestomping

  - Chain of custody
  	- Handover notes 


# Incident Management

- Privacy incidents vs information security incidents
- Know when to talk to legal, users, managers, directors.
- Run a scenario from A to Z, how would you ...

- Good practices for running incidents 
	- How to delegate.
	- Who does what role.
	- How is communication managed + methods of communication.
	- When to stop an attack.
	- Understand risk of alerting attacker.
	- Ways an attacker may clean up / hide their attack.
	- When / how to inform upper management (manage expectations).
	- Metrics to assign Priorities (e.g. what needs to happen until you increase the prio for a case)
	- Use playbooks if available

- Important things to know and understand
	- Type of alerts, how these are triggered.
	- Finding the root cause.
	- Understand stages of an attack (e.g. cyber-killchain)
	- Symptom vs Cause.
	- First principles vs in depth systems knowledge (why both are good).
	- Building timeline of events.
	- Understand why you should assume good intent, and how to work with people rather than against them.
	- Prevent future incidents with the same root cause

  - Response models
  	- SANS' PICERL (Preparation, Identification, Containement, Eradication, Recovery, Lessons learned)
   	- Google's IMAG (Incident Management At Google)


# Coding & Algorithms

- The basics
	- Conditions (if, else).
	- Loops (for loops, while loops).
 	- Dictionaries.
 	- Slices/lists/arrays.
 	- String/array operations (split, contaings, length, regular expressions).
 	- Pseudo code (concisely describing your approach to a problem).

- Data structures
	- Dictionaries / hash tables (array of linked lists, or sometimes a BST).
	- Arrays.
	- Stacks.
	- SQL/tables. 
	- Bigtables.

- Sorting
	- Quicksort, merge sort.

- Searching 
	- Binary vs linear.

- Big O 
	- For space and time.

- Regular expressions
	- O(n), but O(n!) when matching.
	- It's useful to be familiar with basic regex syntax, too.

- Recursion 
	- And why it is rarely used.

- Python
	- List comprehensions and generators [ x for x in range() ].
	- Iterators and generators.
	- Slicing [start:stop:step].
	- Regular expressions.
	- Types (dynamic types), data structures.
	- Pros and cons of Python vs C, Java, etc.
	- Understand common functions very well, be comfortable in the language.


## Security Themed Coding Challenges

These security engineering challenges focus on text parsing and manipulation, basic data structures, and simple logic flows. Give the challenges a go, no need to finish them to completion because all practice helps.

- Cyphers / encryption algorithms 
	- Implement a cypher which converts text to emoji or something.
	- Be able to implement basic cyphers.

- Parse arbitrary logs 
	- Collect logs (of any kind) and write a parser which pulls out specific details (domains, executable names, timestamps etc.)

- Web scrapers 
	- Write a script to scrape information from a website.

- Port scanners 
	- Write a port scanner or detect port scanning.

- Botnets
	- How would you build ssh botnet?

- Password bruteforcer
	- Generate credentials and store successful logins. 

- Scrape metadata from PDFs
	- Write a mini forensics tool to collect identifying information from PDF metadata. 

- Recover deleted items
	- Most software will keep deleted items for ~30 days for recovery. Find out where these are stored. 
	- Write a script to pull these items from local databases. 
 
- Malware signatures
	- A program that looks for malware signatures in binaries and code samples.
	- Look at Yara rules for examples.
 


### By [nolang](https://twitter.com/__nolang)

--------------------
--------------------

# Cyber_Security_Interview_Questions

--------------------

Cyber Security Interview Questions for Penetration Testers, Red Team Engineers, SCO Analyst, Malware Researchers, Network Security Engineers and more. These are real questions faced by candidates in different domain interviews. These questions can help serious Job seekers and students alike who want to enter Cyber Security and clueless what might be asked in Interviews.

Different Cyber Security Job Roles - A look at different domains in Cyber Security, this is not perfect, but still can help to get some idea of different roles one might take in CYber Security Jobs

[Cyber Security Jobs Tweet*](https://twitter.com/abhinavkakku/status/1609385254615420929)
![Cyber Security Jobs](/images/Cyber_Security_Job_Roles.png)

The Tweet above or the MindMap of different possible Cyber Security Job Roles will help me escape the Question - " Why every question is not Offensive or Defensive only, I only want Pentesting Questions, or only SOC Analyst Questions." 
Answer - " Cyber Security is big domain and needs for different roles are different. "

Orginal Repository - https://github.com/abhinavkakku/Cyber_Security_Interview_Questions

Note-1: We will keep updating this page (Last updated : 02 November, 2k23), just started so don't expect this to become encyclopedia yet. I have removed the answers bit for now, might be updated in future.

Note-2: Some questions can fall under more than one Category, forgive me for that, I will try not to repeat. Yet some questions that have very broad scope of follow-up questions maybe repeated ( as it gives context).

--------------------

## Basic Cyber Security Questions

Some basic questions that are very fundamental in nature, are directly or sometimes in-directly related to Cyber Security.
These help establish some baseline, and everytime when one of these questions are asked, try to align the answer to Cyber Security.
Also, when answering these, try not to miss the basic points, often the interviewer might want to hear some particular keyword, so dont rush on hearing a easy question, gather yourself and the answer and answer it.

1. ### What is Cyber Kill Chain?

    The Cyber Kill Chain is a framework developed by Lockheed Martin that outlines the stages of a cyberattack. It helps in understanding and responding to cyber threats. The Cyber Kill Chain consists of the following steps:

    1. **Reconnaissance:** The attacker gathers information about the target.
    2. **Weaponization:** The attacker creates a deliverable payload (e.g., malware).
    3. **Delivery:** The attacker sends the payload to the target (e.g., phishing email).
    4. **Exploitation:** The payload exploits a vulnerability in the target system.
    5. **Installation:** The payload installs a backdoor or other persistent access.
    6. **Command and Control (C2):** The attacker establishes a remote control channel.
    7. **Actions on Objectives:** The attacker performs their intended actions, such as data exfiltration or destruction.

2. ### How can you classify the roles in Cyber Security?

    Cybersecurity roles can be classified into several categories based on their functions:

    1. **Security Management:**
        - Chief Information Security Officer (CISO)
        - IT Security Manager

    2. **Security Engineering:**
        - Security Architect
        - Security Engineer

    3. **Security Operations:**
        - Security Analyst
        - Security Operations Center (SOC) Analyst
        - Incident Responder

    4. **Compliance and Auditing:**
        - IT Auditor
        - Compliance Manager

    5. **Penetration Testing and Red Teaming:**
        - Penetration Tester
        - Red Team Specialist

    6. **Forensics and Investigations:**
        - Digital Forensics Analyst
        - Cyber Crime Investigator

    7. **Risk Management and Policy:**
        - Risk Analyst
        - Security Policy Analyst

    8. **Identity and Access Management (IAM):**
        - IAM Specialist
        - Access Control Analyst

    9. **Application Security:**
        - Application Security Engineer
        - DevSecOps Engineer

3. ### What is the CIA Triangle?

    The CIA Triangle, also known as the CIA Triad, is a fundamental model in information security that focuses on three core principles:

    1. **Confidentiality:** Ensuring that information is not disclosed to unauthorized individuals or systems.
    2. **Integrity:** Ensuring that information is accurate and has not been tampered with or altered by unauthorized parties.
    3. **Availability:** Ensuring that information and resources are accessible to authorized users when needed.

4. ### What’s the difference between symmetric and asymmetric (public-key) cryptography?

    **Symmetric Cryptography:**
    - Uses the same key for both encryption and decryption.
    - Faster and less computationally intensive.
    - Key distribution and management can be challenging because both parties need to securely share the same key.
    - Examples: AES (Advanced Encryption Standard), DES (Data Encryption Standard).

    **Asymmetric Cryptography:**
    - Uses a pair of keys: a public key for encryption and a private key for decryption.
    - More secure for key distribution since the public key can be shared openly.
    - Slower and more computationally intensive compared to symmetric cryptography.
    - Examples: RSA (Rivest-Shamir-Adleman), ECC (Elliptic Curve Cryptography).

5. ### What are Ports in Computers, how many ports does a computer have?

    **Ports in Computers:**
    - Ports are communication endpoints in computer networking used to distinguish between different services or processes running on a networked device.
    - A port is identified by a number, ranging from 0 to 65535, with some ports designated for specific services (e.g., port 80 for HTTP, port 443 for HTTPS).

    **Number of Ports:**
    - There are a total of 65,536 ports (numbered 0 to 65535).
    - Ports 0 to 1023 are known as well-known ports and are typically reserved for system or well-known services.
    - Ports 1024 to 49151 are registered ports, often used for specific services and applications.
    - Ports 49152 to 65535 are dynamic or private ports, usually assigned temporarily for client-side communication.
6. ### Why is deleted data not truly gone when you delete it?

    When you delete data, the operating system removes the reference to the data on the disk, making it no longer accessible to the user. However, the actual data remains on the disk until it is overwritten by new data. This means that with specialized software, it is often possible to recover deleted data.

7. ### What is Encryption, Encoding, Hashing?

    - **Encryption:** The process of converting data into a coded form to prevent unauthorized access. It requires a key to encrypt and decrypt the data. Examples: AES, RSA.
    - **Encoding:** The process of converting data into a different format using a scheme that is publicly available. Encoding is used to ensure data is properly formatted for transmission or storage. Examples: Base64, URL encoding.
    - **Hashing:** The process of converting data into a fixed-size string of characters, which is typically a hash code. Hashing is a one-way process used for data integrity and password storage. Examples: MD5, SHA-256.

8. ### What is Salting (in context of Hashing), and why it is used?

    Salting is the process of adding a unique, random value to each password before it is hashed. This is done to ensure that even if two users have the same password, their hashes will be different. Salting helps to defend against dictionary attacks and rainbow table attacks.

9. ### Would you Encrypt and Compress or Compress and Encrypt? Why?

    It is generally better to **compress before encrypting**. Compressing data reduces its size, making the encryption process faster and more efficient. Additionally, encrypted data often appears random and does not compress well, so compressing after encryption would not be effective.

10. ### What’s the difference between deep web and dark web?

    - **Deep Web:** Refers to parts of the internet not indexed by standard search engines. This includes private databases, internal company sites, and medical records. It is not inherently malicious.
    - **Dark Web:** A subset of the deep web that is intentionally hidden and accessible only with specific software such as Tor. It is often associated with illegal activities.

11. ### What is MITRE ATT&CK?

    MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It is used as a foundation for the development of specific threat models and methodologies in the private sector, government, and the cybersecurity product and service community.

12. ### Explain/differentiate Vulnerability and Exploit

    - **Vulnerability:** A weakness or flaw in a system that can be exploited to compromise the system's security.
    - **Exploit:** A piece of software, code, or sequence of commands that takes advantage of a vulnerability to cause unintended behavior, typically gaining unauthorized access.

13. ### Explain Vulnerability, Threat, and Risk

    - **Vulnerability:** A weakness in a system that can be exploited.
    - **Threat:** A potential cause of an unwanted impact to a system or organization.
    - **Risk:** The potential for loss or damage when a threat exploits a vulnerability. It is often assessed as the combination of the likelihood of the threat occurring and the impact it would have.

14. ### What is the difference in VA and PT?

    - **VA (Vulnerability Assessment):** The process of identifying and prioritizing vulnerabilities in a system. It focuses on discovering vulnerabilities without exploiting them.
    - **PT (Penetration Testing):** A simulated cyber attack against a system to identify and exploit vulnerabilities. It goes beyond identifying vulnerabilities by attempting to exploit them to assess the security of the system.

15. ### What is the difference between Events, Alerts, and Incidents?

    - **Event:** Any observable occurrence in a system or network. Not all events indicate a security issue.
    - **Alert:** A notification or warning generated by a security system when an event or a combination of events indicates a potential security issue.
    - **Incident:** A confirmed security breach or compromise that requires response and remediation.

16. ### What are APT Groups (in Cyber Security Context)?

    APT (Advanced Persistent Threat) groups are sophisticated, well-funded, and skilled adversaries who conduct prolonged and targeted cyberattacks. These groups typically have specific objectives, such as espionage or sabotage, and use a variety of techniques to gain and maintain access to targeted networks.

17. ### Any experience working with any Ticketing tools?

    Ticketing tools are used for managing and tracking incidents, service requests, and other tasks. Some commonly used ticketing tools in cybersecurity include:
    - **Jira**
    - **ServiceNow**
    - **Zendesk**
    - **Remedy**
    - **RT (Request Tracker)**
    - **Freshservice**

    Personal experience with these tools may vary, and they are often used to ensure that incidents and tasks are properly logged, assigned, and resolved in an organized manner.

----------

## Network Security Interview Questions

Questions around Networks and devices are important as this is very intrinsic part of any security setup.
I will again repeat this - while the questions are very very basic, be prepared for follow up questions. These questions are just initiators, the actual question will the follow up question on which you will be judged. 

1. ### What is traceroute and how do you use it?

    Traceroute is a network diagnostic tool used to track the pathway that packets take from one computer to another. It helps to identify the route and measure transit delays of packets across an IP network.

    **Usage:**
    - On Windows: Open Command Prompt and type `tracert [hostname or IP]`.
    - On Linux/Mac: Open Terminal and type `traceroute [hostname or IP]`.

2. ### What is SSH? On what port does SSH work?

    SSH (Secure Shell) is a protocol used to securely log into and execute commands on remote machines. It provides encrypted communication over an insecure network.

    **Port:** SSH typically operates on port 22.

3. ### Can you do SSH from Windows?

    Yes, you can use SSH from Windows. Tools such as PuTTY, OpenSSH (built into Windows 10 and later), and other third-party applications allow SSH connections from Windows.

4. ### Why is DNS Monitoring Important? What information can it reveal?

    DNS monitoring is crucial for ensuring the health and security of DNS infrastructure. It helps in detecting issues such as downtime, misconfigurations, and malicious activities.

    **Reveals:**
    - Unusual traffic patterns indicating potential DDoS attacks.
    - Signs of DNS cache poisoning or spoofing.
    - Performance issues and delays in DNS resolution.
    - Unauthorized changes to DNS records.

5. ### DNS Communication Happens on which port?

    DNS communication typically happens on port 53.

6. ### What is VPN?

    A VPN (Virtual Private Network) extends a private network across a public network, allowing users to send and receive data as if their devices were directly connected to the private network. It provides security, anonymity, and access to restricted resources.

7. ### What is Proxy?

    A proxy server acts as an intermediary between a client and the server from which the client is requesting a service. It can provide various functions like caching, filtering, and anonymizing.

8. ### What is the difference between VPN and Proxy?

    - **VPN:** Encrypts all network traffic between the user's device and the VPN server, providing privacy and security for all online activities.
    - **Proxy:** Intermediates specific types of traffic (e.g., HTTP/HTTPS) and can anonymize or cache requests but typically does not encrypt all traffic.

9. ### What is Forward Proxy and Reverse Proxy?

    - **Forward Proxy:** Acts on behalf of clients, fetching resources from the internet on their behalf.
    - **Reverse Proxy:** Acts on behalf of servers, handling requests from clients on behalf of the servers.

10. ### What is a Load Balancer?

    A load balancer distributes network or application traffic across multiple servers to ensure no single server becomes overwhelmed. It enhances the availability and reliability of applications.

11. ### What is CDN?

    A CDN (Content Delivery Network) is a network of servers distributed globally to deliver content more efficiently to users. It caches content closer to the end-users to reduce latency and improve load times.

12. ### Can you explain man-in-the-middle attack?

    A man-in-the-middle (MitM) attack occurs when an attacker intercepts and potentially alters communication between two parties who believe they are directly communicating with each other.

13. ### Does HTTPS/SSL protect from Man-in-the-Middle Attack?

    Yes, HTTPS/SSL helps protect against MitM attacks by encrypting the communication between the client and server, ensuring data integrity and authenticity.

14. ### What is the difference between IPS and IDS?

    - **IDS (Intrusion Detection System):** Monitors network traffic for suspicious activity and alerts administrators.
    - **IPS (Intrusion Prevention System):** Monitors and actively prevents/block suspicious activities.

15. ### What are different OSI Layers in Networking?

    The OSI model has seven layers:
    1. Physical Layer
    2. Data Link Layer
    3. Network Layer
    4. Transport Layer
    5. Session Layer
    6. Presentation Layer
    7. Application Layer

16. ### How is TCP/IP Layer Different from OSI Layers in Networking?

    The TCP/IP model has four layers, which correspond to the OSI model's layers:
    1. Network Interface Layer (OSI: Physical and Data Link)
    2. Internet Layer (OSI: Network)
    3. Transport Layer (OSI: Transport)
    4. Application Layer (OSI: Session, Presentation, and Application)

17. ### Do you prefer filtered ports or closed ports on your firewall?

    **Filtered ports** are preferable because they do not respond to probes, making it harder for attackers to detect the presence of services, thereby reducing the attack surface.

18. ### What is a firewall? What are different types of Firewall?

    A firewall is a security device that monitors and controls incoming and outgoing network traffic based on predetermined security rules.

    **Types:**
    - Packet-Filtering Firewall
    - Stateful Inspection Firewall
    - Proxy Firewall
    - Next-Generation Firewall (NGFW)
    - Network Address Translation (NAT) Firewall

19. ### How can you bypass a firewall or IDS?

    Techniques to bypass firewalls or IDS include:
    - Using encrypted tunnels (e.g., VPN, SSH)
    - Steganography
    - Fragmenting packets
    - Tunneling protocols through allowed ports (e.g., HTTP, HTTPS)

20. ### What is Fragmentation attack?

    A fragmentation attack involves sending fragmented packets to a target in an attempt to bypass security mechanisms that inspect packets for malicious content.

21. ### How can Fragmentation be used as a DoS Attack? How can this be avoided or handled?

    Fragmentation attacks can overwhelm a target's resources by sending numerous fragmented packets, causing the system to consume resources to reassemble them.

    **Mitigation:**
    - Implementing fragmentation reassembly timeouts.
    - Using advanced firewalls and IDS/IPS to detect and block malformed fragments.

22. ### Besides firewalls, what other devices are used to enforce network boundaries?

    - Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS)
    - Routers with access control lists (ACLs)
    - Network Access Control (NAC) devices
    - Honeypots and honeynets
    - Security gateways

23. ### What is a honeypot?

    A honeypot is a decoy system or network set up to attract and detect attackers. It is used to study attack methods and gather intelligence about potential threats.

24. ### What is the difference between an HIDS and a NIDS? Examples of both.

    - **HIDS (Host-based Intrusion Detection System):** Monitors and analyzes the internals of a computing system. Example: OSSEC.
    - **NIDS (Network-based Intrusion Detection System):** Monitors and analyzes network traffic for suspicious activities. Example: Snort.

25. ### What is worse in detection, a false negative or a false positive? And why?

    A **false negative** is worse because it means a real attack or threat has not been detected, leaving the system vulnerable. False positives, while disruptive, do not pose a direct threat to security.

26. ### What is DDoS and DoS attack?

    - **DoS (Denial of Service):** An attack intended to shut down a machine or network, making it inaccessible to its intended users by overwhelming it with traffic.
    - **DDoS (Distributed Denial of Service):** A more severe form of DoS attack where multiple systems (often compromised) are used to flood the target with traffic.

27. ### What do you understand by IP Subnetting?

    IP subnetting is the process of dividing a larger network into smaller subnetworks (subnets) to improve network performance and manageability. Each subnet has a specific range of IP addresses.

28. ### Explain NAT (Network Address Translation)?

    NAT is a method used to map multiple private IP addresses to a single public IP address (or a few) to conserve the number of public IP addresses used. It provides security by hiding internal IP addresses from external networks.

29. ### What is Port Forwarding? And how/why it is used?

    Port forwarding is a technique used to redirect traffic from one IP address and port number combination to another. It is used to provide access to internal network services from an external network.

30. ### What is VLAN?

    A VLAN (Virtual Local Area Network) is a logical grouping of devices on a network that can communicate as if they were on the same physical LAN, regardless of their physical location. VLANs improve network efficiency and security.

31. ### What Security Principle means a signed message came from the owner of the key that signed it? (non-repudiation, Integrity, authority, non-verifiability)

    **Non-repudiation** ensures that a signed message came from the owner of the key that signed it, preventing the sender from denying the authenticity of their signature.

32. ### What is ARP Poisoning?

    ARP poisoning is a technique used by attackers to manipulate the ARP (Address Resolution Protocol) cache of network devices. By sending spoofed ARP messages, attackers can associate their MAC address with the IP address of another device, allowing them to intercept, modify, or disrupt traffic.

-----------------

## Intermediate Level Questions

Now that you have answered some basic questions, lets level up a bit.
These might not be very good, but keeping in mind to keep answer to the realm of Security, focus on security aspect when answering these.

1. ### What is Three-way Handshake? Explain.

    The three-way handshake is a process used in TCP/IP networks to establish a connection between a client and a server. It ensures that both parties are ready to transmit data and agree on the initial sequence numbers.

    **Steps:**
    - **SYN:** The client sends a TCP segment with the SYN (synchronize) flag set to the server to initiate a connection.
    - **SYN-ACK:** The server responds with a TCP segment with both SYN and ACK (acknowledgment) flags set, acknowledging the client's request and indicating its readiness.
    - **ACK:** The client sends a final acknowledgment (ACK) back to the server, confirming the connection is established.

2. ### How many packets are sent and received in a 3-way handshake?

    A total of three packets are exchanged:
    - **Packet 1:** Client to server (SYN).
    - **Packet 2:** Server to client (SYN-ACK).
    - **Packet 3:** Client to server (ACK).

3. ### Explain Brute Force Attack. How do you detect it?

    **Brute Force Attack:** A method where an attacker tries all possible combinations of passwords or encryption keys until the correct one is found.

    **Detection:**
    - **Unusual Login Attempts:** Multiple failed login attempts from a single IP address or across many accounts.
    - **Log Analysis:** Checking logs for repetitive patterns of failed logins.
    - **Account Lockouts:** Sudden increase in account lockouts.

5. ### How can you prevent Brute Force attack? Mention some methods.

    - **Account Lockout Policies:** Temporarily lock accounts after a certain number of failed login attempts.
    - **CAPTCHA:** Implement CAPTCHA to prevent automated login attempts.
    - **Rate Limiting:** Limit the number of login attempts from a single IP address.
    - **Multi-Factor Authentication (MFA):** Require additional verification beyond just a password.
    - **Strong Password Policies:** Encourage or enforce the use of complex passwords.

6. ### Have you heard of 2FA? How does 2FA protect users? Is it possible to bypass 2FA with Phishing?

    **2FA (Two-Factor Authentication):** An additional layer of security that requires not only a password and username but also something that the user has on them, i.e., a physical token or a code sent to their mobile device.

    **Protection:**
    - **Extra Layer:** Even if the password is compromised, the attacker still needs the second factor (e.g., a code or biometric verification).
    - **Phishing Bypass:** Yes, it is possible to bypass 2FA with advanced phishing techniques like man-in-the-middle attacks, where the attacker intercepts the 2FA code or redirects the victim to a fake login page.

7. ### What is the difference between SSL and TLS?

    **SSL (Secure Sockets Layer):** An older protocol for encrypting information sent over the internet. It has known vulnerabilities and is deprecated.

    **TLS (Transport Layer Security):** The successor to SSL, providing improved security features and performance. Modern implementations use TLS instead of SSL.

8. ### What is the use of SSL? How does it protect?

    **Use:** SSL/TLS is used to encrypt data transmitted between a client and a server, ensuring privacy and data integrity.

    **Protection:**
    - **Encryption:** Data is encrypted, preventing eavesdropping.
    - **Authentication:** Ensures the server is who it claims to be through certificates.
    - **Data Integrity:** Protects data from being tampered with during transmission.

9. ### How does SSL Certificate Exchange happen?

    **SSL Certificate Exchange:**
    - **Handshake Initiation:** Client sends a "ClientHello" message with supported protocols and encryption methods.
    - **Server Response:** Server responds with a "ServerHello" message and sends its certificate.
    - **Verification:** Client verifies the server's certificate against trusted Certificate Authorities (CAs).
    - **Session Key:** Client and server agree on a session key using asymmetric encryption, which is then used for symmetric encryption of data.

10. ### What do you understand by DMZ and Non-DMZ?

    **DMZ (Demilitarized Zone):** A physical or logical subnetwork that separates an internal local area network (LAN) from other untrusted networks, typically the internet. It adds an additional layer of security to an organization's LAN.

    **Non-DMZ:** The internal network that is protected and not exposed to external networks. It contains sensitive systems and data.

12. ### What is Metadata and how can you view it? What Risk does it cause?

    **Metadata:** Data that provides information about other data, such as creation date, author, file size, and more.

    **Viewing Metadata:**
    - **Files:** Right-click on files and view properties/details.
    - **Documents:** Use tools like ExifTool for detailed metadata analysis.

    **Risks:**
    - **Privacy Leaks:** Reveals information about the user or the system.
    - **Sensitive Data Exposure:** May contain confidential information.
    - **Attack Surface:** Can provide attackers with information to exploit vulnerabilities.

13. ### Explain TCP and UDP. How do they differ?

    **TCP (Transmission Control Protocol):**
    - **Connection-oriented:** Establishes a connection before data transfer.
    - **Reliability:** Ensures data delivery through acknowledgments and retransmissions.
    - **Order:** Maintains the order of data packets.

    **UDP (User Datagram Protocol):**
    - **Connectionless:** No need to establish a connection before data transfer.
    - **Speed:** Faster due to no error-checking or acknowledgment.
    - **Best Effort:** Does not guarantee delivery, order, or integrity.

14. ### What is DNS? How does DNS Resolution happen? Which Port is used for DNS? Is it over TCP or UDP?

    **DNS (Domain Name System):** Translates domain names into IP addresses.

    **DNS Resolution:**
    - **Query:** A client sends a DNS query to a DNS server.
    - **Recursive Query:** The DNS server queries other DNS servers recursively if it does not have the answer.
    - **Response:** The DNS server sends back the IP address associated with the domain name.

    **Port:** DNS typically uses port 53.

    **Protocols:** 
    - **UDP:** Used for standard queries due to lower overhead.
    - **TCP:** Used for zone transfers and when responses exceed 512 bytes.

15. ### What is DLP? Heard of it?

    **DLP (Data Loss Prevention):** A set of tools and processes used to ensure sensitive data is not lost, misused, or accessed by unauthorized users. It helps in protecting data in motion, data at rest, and data in use.

16. ### What is Data Exfiltration? Mention some methods of Data Exfiltration.

    **Data Exfiltration:** Unauthorized transfer of data from a system.

    **Methods:**
    - **Network Traffic:** Transferring data over the network to an external server.
    - **Removable Media:** Copying data to USB drives or external hard disks.
    - **Steganography:** Hiding data within other files like images.
    - **Email:** Sending sensitive data via email to external addresses.
    - **Cloud Storage:** Uploading data to cloud services.

17. ### How can you check for Data Exfiltration Activities?

    - **Network Monitoring:** Inspect outbound traffic for unusual patterns or large data transfers.
    - **DLP Solutions:** Use DLP tools to monitor, detect, and prevent unauthorized data transfers.
    - **Log Analysis:** Analyze logs for signs of unauthorized access or data transfers.
    - **Endpoint Security:** Monitor and control the use of removable media and cloud services.

18. ### Common Ports and Services, like SMB, DNS FTP, SSH, SMTP, HTTP, HTTPS, DHCP. What steps do you take if you observe too much traffic to/from on port 22?

    **Steps:**
    - **Monitor Traffic:** Use network monitoring tools to analyze the traffic and identify sources and destinations.
    - **Investigate:** Check for authorized SSH usage and potential brute force attacks.
    - **Limit Access:** Restrict SSH access to trusted IP addresses or VPN connections.
    - **Update Configurations:** Ensure SSH configurations follow best security practices (e.g., disable root login, use key-based authentication).
    - **Intrusion Detection:** Deploy IDS/IPS to detect and alert on suspicious activities.

19. ### How do you place a firewall, load balancer, proxy? In what order and why?

    **Order:**
    - **Firewall:** First line of defense to filter incoming and outgoing traffic based on security rules.
    - **Load Balancer:** Distributes incoming traffic across multiple servers to ensure availability and reliability.
    - **Proxy:** Acts as an intermediary for requests, providing additional security, caching, and anonymity.

    **Reason:** 
    - The firewall provides the initial security barrier.
    - The load balancer ensures efficient resource utilization and availability.
    - The proxy offers additional security and functionality without directly exposing internal servers.

20. ### What information can you get from a MAC Address?

    - **Manufacturer:** The first half of the MAC address (Organizationally Unique Identifier) identifies the manufacturer of the device.
    - **Device Type:** Sometimes the MAC address can indicate the type of device.
    - **Network Interface:** Identifies the specific network interface on a device.

21. ### What port does PING work on?

    **Ping:** Uses the Internet Control Message Protocol (ICMP), which does not operate on a specific port but rather on the network layer of the OSI model.

22. ### Describe TCP Flow Control mechanism.

    **TCP Flow Control:** Ensures that the sender does not overwhelm the receiver by sending too much data too quickly. It uses a sliding window mechanism where the receiver specifies the amount of data it can handle (window size).

23. ### Describe packet loss recovery mechanism in TCP.

    **TCP Packet Loss Recovery:**
    - **Retransmission:** Lost packets are retransmitted based on acknowledgments (ACKs) received.
    - **Timeouts:** If an ACK is not received within a certain timeframe, the packet is retransmitted.
    - **Duplicate ACKs:** Receipt of multiple duplicate ACKs triggers fast retransmission before timeout occurs.

24. ### Explain how in Linux terminal can you confirm if it is a file or a directory?

    **Commands:**
    - **ls -l:** Lists files and directories with details (d indicates directory, - indicates file).
    - **file [name]:** Determines the type of file.
    - **stat [name]:** Provides detailed file or directory information.

25. ### Explain Redirections in Linux.

    **Redirections:**
    - **Standard Output (>):** Redirects output to a file.
    - **Standard Input (<):** Redirects input from a file.
    - **Standard Error (2>):** Redirects error messages to a file.
    - **Appending (>>):** Appends output to the end of a file without overwriting.

    **Example:**
    ```bash
    command > file.txt   # Redirects output to file.txt
    command < input.txt  # Takes input from input.txt
    command 2> error.log # Redirects errors to error.log
    command >> file.txt  # Appends output to file.txt
    ```

26. ### What are pipes? Explain named Pipe.

    **Pipes:** Allow the output of one command to be used as the input to another command.

    **Example:**
    ```bash
    ls | grep "pattern"  # Uses output of 'ls' as input to 'grep'
    ```

    **Named Pipe (FIFO):** A special type of file that acts as a conduit for passing information between processes. It persists in the file system.

    **Example:**
    ```bash
    mkfifo mypipe        # Create a named pipe
    echo "data" > mypipe # Write to named pipe
    cat < mypipe         # Read from named pipe
    ```
----

## Red Teaming, Penetration Testing,  Application Security Questions

When explaining any Vulnerability here, also try mentioning remidiation for the same, and more deep dive if follow up questions asked.

Note : Kindly dont pinpoint yet on hey this is patching or this is Application Security or This falls in Mobile PT or Red Teaming, the border lines between these bit blured, so questions cn fall in one or more categories. 



### Pentesting (Network/Endpoints)

Again, the questions here are not guessed, can be limitless, so just putting very basic ones. This does NOT pertains to like - Hey ! These are asked in Pentesting Interviews.

1. ### How do you start about hacking a target? What is Information Gathering, Enumeration?

    **Information Gathering:** The first step in hacking a target is to collect as much information as possible about the target. This includes gathering publicly available information (OSINT), using tools like Whois, DNS enumeration, and social engineering.

    **Enumeration:** This involves active interaction with the target systems to discover additional details such as open ports, services running on those ports, usernames, and shared resources. Tools like Nmap and Netcat are commonly used.

2. ### What are phases of Network Penetration Testing? (Cyber Kill Chain)

    **Phases of Network Penetration Testing:**
    - **Reconnaissance:** Gathering information about the target.
    - **Scanning:** Identifying open ports and services.
    - **Enumeration:** Extracting more detailed information from the target.
    - **Exploitation:** Gaining access by exploiting vulnerabilities.
    - **Post-Exploitation:** Maintaining access and gathering additional data.
    - **Reporting:** Documenting findings and providing recommendations.

3. ### What NMAP argument/flag in nmap tells about version?

    **Flag:** `-sV`
    - Example: `nmap -sV <target>`

4. ### What is the difference in -v and -V in NMAP?

    **-v:** Enables verbose output, providing more detailed information during the scan process.
    **-V:** Displays the version of Nmap.

5. ### Can SQLi lead to RCE?

    **Yes:** SQL Injection (SQLi) can potentially lead to Remote Code Execution (RCE) if the injected SQL code allows execution of arbitrary commands on the underlying operating system.

6. ### How do you erase tracks when hacked a machine? Consider it is Linux.

    **Erasing Tracks:**
    - **Clear Logs:** Delete or modify system logs (e.g., `/var/log/`).
    - **History:** Clear command history (`history -c`).
    - **Network Traces:** Remove evidence of network connections.
    - **Files:** Delete temporary files and artifacts created during the attack.

7. ### What is your opinion on Automated Pentesting vs Manual Pentesting? Which one is better?

    **Automated Pentesting:** Fast and efficient for identifying known vulnerabilities using tools like Nessus and OpenVAS.
    
    **Manual Pentesting:** Provides deeper insights, creativity, and the ability to find complex vulnerabilities that automated tools might miss.

    **Better Approach:** A combination of both is ideal. Automated tools for initial scanning and manual testing for thorough assessment.

8. ### What is the difference in Black-Box Pentesting vs White-Box Pentesting?

    **Black-Box Pentesting:** Testers have no prior knowledge of the target environment. Simulates an external attacker.

    **White-Box Pentesting:** Testers have full knowledge of the target environment, including source code and network architecture. Simulates an insider attack.

9. ### Any Purple Teaming Exercises done in the past? Explain.

    **Purple Teaming:** A collaborative approach where Red Team (attackers) and Blue Team (defenders) work together to improve an organization's security posture. Red Team tests the defenses, while Blue Team actively defends and learns from the attack techniques.

10. ### Have you done any Phishing assessments in the past?

    **Phishing Assessments:** Involves creating simulated phishing campaigns to test the organization's awareness and response to phishing attacks. It includes crafting emails that lure users into clicking malicious links or divulging sensitive information.

11. ### How can you bypass Antivirus Detection? Explain.

    **Bypassing Antivirus:**
    - **Obfuscation:** Modify the payload to evade signature-based detection.
    - **Encryption:** Encrypt the payload and decrypt it in memory.
    - **Polymorphic Code:** Change the code structure on each execution.
    - **Living-off-the-land:** Use legitimate tools and scripts to perform malicious actions.

12. ### How does EDR work? How to bypass EDR Detections? Explain.

    **EDR (Endpoint Detection and Response):** Monitors endpoints for suspicious activities, logs, and detects potential threats using behavior analysis.

    **Bypassing EDR:**
    - **Process Injection:** Inject code into trusted processes.
    - **Fileless Malware:** Operate entirely in memory to avoid detection.
    - **Living-off-the-land:** Use built-in system tools to perform actions.

13. ### What is a Supply Chain Attack?

    **Supply Chain Attack:** An attack targeting the less-secure elements of a supply chain to compromise a target. It often involves injecting malicious code into software updates or hardware components.

14. ### Compromising a local account is easier or an AD account? (Windows Context)

    **Local Account:** Generally easier due to typically weaker security measures and fewer monitoring tools compared to Active Directory (AD) accounts, which are usually more heavily protected and monitored.

15. ### How would you do Data Exfiltration if you hacked a machine?

    **Methods:**
    - **Network Transfer:** Use protocols like FTP, HTTP, or DNS tunneling.
    - **Removable Media:** Copy data to USB drives.
    - **Steganography:** Hide data within other files.
    - **Email:** Send data via email.

16. ### Have you worked on Nessus / Qualys before?

    **Nessus / Qualys:** Both are widely used vulnerability scanners for identifying and assessing vulnerabilities in networks and systems.

17. ### Any open-source alternative of Nessus or Qualys?

    **Open Source Alternatives:**
    - **OpenVAS**
    - **Nmap**
    - **OWASP ZAP**

18. ### What do you prefer? Vulnerability Assessment of a machine with Credentials or without Credentials?

    **With Credentials:** Provides a more comprehensive assessment by allowing deeper inspection of the system, identifying more vulnerabilities.

19. ### What are things to consider before doing Pentesting or Vulnerability Assessment of a target?

    **Considerations:**
    - **Scope:** Define the boundaries and extent of testing.
    - **Permissions:** Obtain necessary authorizations.
    - **Impact:** Assess potential impact on operations.
    - **Timing:** Schedule to minimize disruption.
    - **Tools and Techniques:** Plan the tools and methods to be used.

20. ### Would you place the machine (server example Nessus) within the same Network of machines which is being tested or separate?

    **Separate Network:** To avoid potential impacts on the production environment and ensure the testing environment is isolated.

21. ### Why or why not will you whitelist the Source machine of attack in Penetration Testing or Vulnerability Assessment?

    **Whitelisting Source Machine:**
    - **Pros:** Ensures the test traffic is not blocked, allowing comprehensive assessment.
    - **Cons:** Might not reflect real-world scenarios where attackers are not whitelisted.

22. ### How do you rate Vulnerability? Explain scoring system or frameworks.

    **Scoring System:**
    - **CVSS (Common Vulnerability Scoring System):** Provides a standardized way to assess the severity of vulnerabilities based on factors like exploitability and impact.
    - **OWASP Risk Rating Methodology:** Evaluates risk based on factors like likelihood and impact.

23. ### Name some tools you use in Network Pentesting.

    **Tools:**
    - **Nmap**
    - **Metasploit**
    - **Wireshark**
    - **Burp Suite**
    - **Nikto**

24. ### How do you report Vulnerability or Security Gaps after pentesting? (Report Writing)

    **Reporting:**
    - **Executive Summary:** High-level overview of findings and recommendations.
    - **Technical Details:** In-depth description of each vulnerability, including steps to reproduce, impact, and mitigation.
    - **Screenshots and Logs:** Provide evidence of findings.
    - **Remediation Plan:** Suggested actions to fix identified vulnerabilities.

25. ### Do you work often with patching teams to report and get patched the vulnerable software or fixing security gaps?

    **Collaboration:** Yes, regularly working with patching teams to ensure identified vulnerabilities are properly addressed and remediated.

26. ### What are some HTTP Status codes you monitor during pentest? Explain some interesting ones.

    **Status Codes:**
    - **200 OK:** Successful request.
    - **301 Moved Permanently:** Resource moved permanently.
    - **401 Unauthorized:** Authentication required.
    - **403 Forbidden:** Access denied.
    - **404 Not Found:** Resource not found.
    - **500 Internal Server Error:** Server encountered an error.

27. ### What is a 0-Day (Zero-Day) attack?

    **0-Day Attack:** An attack that exploits a previously unknown vulnerability, giving the vendor zero days to address and patch the issue.

28. ### What is Sub-Domain Takeover. Explain.

    **Sub-Domain Takeover:** Occurs when a sub-domain points to an external service that has been removed or is no longer in use, allowing an attacker to take control of the sub-domain by registering the service.

29. ### How can you detect presence of a WAF (Web Application Firewall), and which one?

    **Detection:**
    - **Fingerprinting:** Analyze HTTP responses for headers and patterns specific to WAFs.
    - **Tools:** Use tools like WAFW00f to detect and identify WAFs.

30. ### What is a C2 Server (Command and Control)?

    **C2 Server:** A server used by attackers to communicate with compromised machines, send commands, and receive stolen data.

31. ### Mention some SSL/TLS related Vulnerabilities.

    **Vulnerabilities:**
    - **Heartbleed:** Exploits a flaw in OpenSSL, allowing data leakage.
    - **POODLE:** Exploits weaknesses in SSL 3.0.
    - **BEAST:** Exploits vulnerabilities in TLS 1.0.
    - **Logjam:** Downgrade attack on Diffie-Hellman key exchange.

32. ### Have you come across any recent Data Breach, explain how it happened. (and IR Part: How we can protect against the same?)

    **Example:**
    - **Capital One Data Breach (2019):** Exploited a misconfigured firewall to access sensitive data.
    - **IR:** Regular security audits, proper configuration management, and timely patching.

33. ### How does NMAP determine the Operating System of the target?

    **OS Detection:** Nmap uses TCP/IP stack fingerprinting by analyzing responses to various probes and comparing them to its database of known fingerprints.

34. ### What is the difference in Pass-the-Hash and Pass-the-Ticket?

    **Pass-the-Hash:** Uses hashed passwords to authenticate without knowing the plaintext password.
    **Pass-the-Ticket:** Uses Kerberos tickets (TGTs) to authenticate and access network resources without needing the password hash.




## Application Security

1. Heard of OWASP ? What is it ? name some Vulnerabilities from OWASP-T10.
1. What is Vulnerability Assesment, Pentesting , and Red teaming. Differences ?
2. How do you handle Brute Forcing on your application ?
3. What is Authentication and Authorization ? 
4. What is Steteful and Steteless in HTTP context ?
4. How does HTTP handles state ?
5. What is Cross Site Scripting ? 
6. What is difference in stored , reflected, and DOM XSS ?
7. Which of the XSS attacks are hard to detetct and why ?
7. What is the defense against XSS ? Remidiation. 
6. Do you prefer black-listing approach or whitelisting approach ? and Why ?
7. What is CSRF ? Impact ? and Remidiation ?
8. When investigating CSRF Attack , wat are the things you will look for ?
8. Can you perform CSRF attack if HTTP method is PUT considering there is no CSRF Prevention, Explain?
9. How do you determine if the Website is hosted on IIS or Apache or Nginix or whatever server stack ?
10. What is SQL Injection ?
11. Name some Types of SQL Injection Vulnerability. 
11. Explain Union Based SQL Injection.
11. Explain Time Based SQL Injection.
11. Explain Blind SQL Injection.
12. How do you protect against SQLi ?
13. What is Prepared Statements and Paramatrized Query ? (in Context of SQLi)
13. What is 2nd-Order-SQLi ?
14. How do you store password for applications in database ?
15. What is RCE ? How do you test for RCE ? How can this bug be remidiated ?
16. Explain OS Command Injection .
17. What is CORS ? and SOP ?
18. Does CORS protect against CSRF Attack ?
19. Explain XXE ? What causes this flaw ? How do you mitigate it ? 
20. What are some Security headers in HTTP Request? Name some.
20. Mention some HTTP Response Headers for Security ? Explain.
20. What are various HTTP methods ?
20. What is difference in GET POST and PUT Request ?
21. What is CSP (Content Security Policy) ?
22. Explain Race Condition ? How can you test for it ?
23. Explain Cookie Attributes/Flags ? and Explain.
23. What is Threat Modeling ?
25. When do you interact with developers for security testing ?
25. Are you aware of the Software Development Life Cycle ?
26. When in SDLC should you engage with Developers ?
27. What is CI/CD Pipeline ?  Explain the role of this with the context of Security.
28. Classify some Web Vulnerabilities into Low, Medium , High and Critical category. Reason why !
29. Known that MD5 is not the most secured hasing Algorithm, Why we dont use SHA256 or others always ?
30. Internet facing NGINIX is being used in front of multiple applications (micro service architecture). These application are accessible to users via different sub-domains through NGINIX, What can go Wrong ?
31. Can server SSL Certificate prevent SSL Injection against your system ? Explain.
32. An Attacker is trying to extract session cookie using XSS Vulnerability, but a blank popup is shown. What could be the reason for this behaviour ?
33. Web Application allows user to download their account statement in DF format. How can you securely implement this functionality ? Explain.
34. What is Threat Model / Threat Modeling ?
34. What is STRIDE ?

### Mobile Application Pentesting
1. ### What are some common Risks in Mobile Applications?

    **Common Risks:**
    - **Insecure Data Storage:** Storing sensitive data without encryption.
    - **Weak Server-Side Controls:** Insufficient security on the server side.
    - **Insecure Communication:** Lack of encryption for data in transit.
    - **Insecure Authentication and Authorization:** Weak or improperly implemented authentication mechanisms.
    - **Client-Side Injection:** Vulnerabilities like SQL injection and code injection in the app.
    - **Poor Code Quality:** Code vulnerabilities due to poor coding practices.
    - **Improper Session Handling:** Insecure session management practices.
    - **Insufficient Logging and Monitoring:** Lack of proper logging for security events.
    - **Insecure Third-Party Libraries:** Use of vulnerable or outdated libraries.

2. ### Describe Programmatic ways to detect if iOS or Android device is jailbroken or rooted.

    **iOS Jailbreak Detection:**
    - **Check for Jailbreak Files:** Look for files like `/Applications/Cydia.app`, `/Library/MobileSubstrate/MobileSubstrate.dylib`.
    - **Check for OpenSSH:** Attempt to connect to SSH service running on the device.
    - **System Call Checks:** Verify if sandbox restrictions are lifted using system calls.
    
    **Android Root Detection:**
    - **Check for Root Files:** Look for files like `/system/xbin/su`, `/system/bin/su`.
    - **Check for BusyBox:** Presence of BusyBox installation.
    - **System Properties:** Check for system properties indicating root.
    - **Execute Commands:** Attempt to execute root commands like `su`.

3. ### Can SMS be used as a medium to perform SQL Injection on Android Application? Explain.

    **Yes:** If an Android application processes SMS messages and directly incorporates SMS content into SQL queries without proper validation and sanitization, it can be susceptible to SQL injection attacks.

4. ### Which tool is (mostly*) used to hook into iOS application?

    **Tool:** Frida
    - **Frida:** A dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. It allows you to inject custom scripts into black box processes.

5. ### Which protection mechanism is used for distributing Apple iOS Application on iTunes store?

    **Protection Mechanism:** Digital Rights Management (DRM)
    - **DRM:** Apple uses DRM to protect applications distributed through the iTunes Store, ensuring only authorized users can install and run the apps.

6. ### What are different Obfuscators used to Protect Mobile Apps?

    **Obfuscators:**
    - **ProGuard:** Commonly used for Android applications.
    - **DexGuard:** Advanced version of ProGuard for Android.
    - **R8:** Google's replacement for ProGuard in Android.
    - **iXGuard:** Used for iOS applications.
    - **JSCObfuscator:** For JavaScript code used in hybrid mobile apps.

7. ### What are different ways for Mobile Application to store and Protect sensitive data in Android and iOS? Recommend best practices.

    **Android:**
    - **Encrypted Shared Preferences:** Securely store key-value pairs.
    - **SQLCipher:** Encrypt SQLite database.
    - **Keystore System:** Store cryptographic keys securely.
    
    **iOS:**
    - **Keychain Services:** Securely store passwords and keys.
    - **Data Protection API:** Encrypt files on disk.

    **Best Practices:**
    - **Encryption:** Use strong encryption algorithms.
    - **Secure Storage APIs:** Utilize platform-provided secure storage mechanisms.
    - **Minimize Data Storage:** Store only essential data.
    - **Regular Updates:** Keep libraries and frameworks up-to-date.

8. ### Brief about the Security improvements in Recent (last 2) Android Releases.

    **Recent Security Improvements:**
    - **Scoped Storage:** Limits access to external storage.
    - **BiometricPrompt API:** Enhanced biometric authentication.
    - **Background Location Access:** Restricts location access in background.
    - **Security Updates via Google Play:** Faster security patch deployment.
    - **Enhanced Permissions:** Improved permission management for apps.

9. ### Mention different steps you would perform doing reverse engineering on an iOS Application downloaded from iTunes Store.

    **Steps:**
    - **Extract IPA:** Download and extract the IPA file.
    - **Decrypt Binary:** Use a tool like `frida-ios-dump` to decrypt the binary.
    - **Class Dump:** Use `class-dump` to generate class headers.
    - **Disassemble Binary:** Use a disassembler like Hopper or IDA Pro.
    - **Analyze Code:** Review the disassembled code to understand app logic.
    - **Dynamic Analysis:** Use tools like Frida for runtime analysis and hooking.

10. ### Consider that you have decompiled an Android Application, made changes to the code and apk design. Will you be able to install this repacked APK on a newly formatted Android device? Why or Why not?

    **No:** Because the original APK's signature would be invalidated after modification. Android devices enforce signature verification, and without a valid signature, the APK cannot be installed. You would need to sign the APK with a valid developer key.

11. ### Provide ADB command with example to fetch APK file from Android Device.

    **Command:**
    ```bash
    adb shell pm list packages -f    # Lists all installed packages with their paths
    adb pull /data/app/com.example.app-1/base.apk ./app.apk  # Fetch the APK file
    ```

12. ### Can Android malware App extract sqlite file of another app? How? Why? or Not? Explain with any assumptions made.

    **No:** By default, Android enforces strict sandboxing, preventing apps from accessing each other's data directories, including SQLite databases. However, if the device is rooted or if there are vulnerabilities in the OS, it might be possible.

13. ### Explain different approaches of bypassing SSL Pinning in Android and iOS Applications.

    **Bypassing SSL Pinning:**
    - **Android:**
        - **Frida:** Use Frida scripts to hook SSL functions and bypass pinning checks.
        - **Xposed Framework:** Modules like `JustTrustMe` can disable pinning.
    - **iOS:**
        - **Frida:** Similar to Android, use Frida scripts for bypassing.
        - **Objection:** Dynamic instrumentation to bypass SSL pinning.
    - **Common Methods:**
        - **Code Modification:** Decompile the app, modify the pinning logic, and recompile.
        - **Proxy Tools:** Use tools like Burp Suite with SSL Unpinning plugins.

14. ### How do you start about hacking a target? What is Information Gathering, Enumeration?

    **Information Gathering:** The first step in hacking a target is to collect as much information as possible about the target. This includes gathering publicly available information (OSINT), using tools like Whois, DNS enumeration, and social engineering.

    **Enumeration:** This involves active interaction with the target systems to discover additional details such as open ports, services running on those ports, usernames, and shared resources. Tools like Nmap and Netcat are commonly used.


## Cloud Pentesting or Security

1. What are common Misconfigurations around AWS S3 bucket ? 

----

## SOC Analyst | Incident Response | DFIR

SOC Analysts can be Clark Kent (superman) touching multiple parts of tech, having a grip over some and idea of many helps many times. Also the questions in a basic SOC job can start from any section above or below and land to this part of page. I will try to keep it concise to the topic.

Note : SOC Analysts work around many different tech, so questions expect to judge the knowledge around some system, which can make response (or handling) around some Incident/Attack better. 

Note-2 : Questions in SOC Analyst Role and Incident Response are expected to be asnwered with scenarios and response action, so cover all possible paths you can think of.

1. How can you break password of BIOS on a locked machine. How to do same on Laptop ( expected follow-up).
2. Where is password Stored in Windows Machines ?
3. How can you read SAM File in Windows ? How does it stores passwords ?
4. Mention some methods you crack Windows Password.
5. Lets talk about Linux system passwords , where is it stored ? which hash it uses ? 
6. How can you detect malicious activity around both SAM and passwd/shadow file respectively ? ( say things you should be monitoring and how ?)
7. What is Incident Response ?
8. What is LifeCycle of a Incident Response Process ?
8. What is SLA ?
8. I hope you understand the Idea of P0, P1.2.3.4 Incidents ? Which one will you handle with priority ?
8. What is IOC (Indicators of Compromise) and IOA (Indicators of Attack) ?
9. How can you say if an email is Phishing or not ?
10. What will you do if user reports to have phishing email ?
11. You discover user clicked links in phishing email, also shared credentials. What actions will be taken by you ?
12. SPM DKIM DMARC records are related to ?
13. How can you determine if the email spam ? what is the action taken to arrest the spread of same if you have to act ?
14. make a playbook for case of BEC ( Business Email Compromise ).
15. When a user reports their machine is hacked , what are the things yu look for ?
15. What are some malware persistence Techniques ? 
16. What is Process Injection ? Name some (sub)methods.
17. Which one is more acceptable Sypware or PUP ?
18. What would you prefer on your system ? Rootkit or Backdoor ?
19. Why Ransomware is a buzz word ?
19. How can you detect/confirm that you (organisation) has been hit (affected) by ransomware ? What are the indicators ?
19. How do you respond to a Ransomware attack ?
20. Have you worked on any EDR Tools before ? What makes EDR different from Antivirus ?
21. How/Why would you classify a website as malicious ?
21. What is drive-by-downloads ?
21. Can website with Green-Lock (SSL) be dangerous ? 
22. You discover your Infrastructure / Application is under DDoS attack ? What will be your resonse plan ?
23. How would you advise backup policy of critical data in infrastructure ?
24. What are some interesting logs you can collect in Windows Environment ?
26. What are different DNS Records ? Explain.
27. Explain DNS Exfiltration. How to detect DNS Exfiltration ?
28. Browser, Application and OS are Vulnerable, which one will you priotize to fix and why ?
29. How can you do Network Packet Analysis ? (Wireshark)
30. Can you do do Network Packet Analysis with Wireshark ? What all information can you get from this analysis ?
31. Can you do Network backet Analysis of HTTPS (SSL Enabled) traffic with Wireshark ?
24. What are the logs from a Linux machine you would pick for SIEM ?
24. What is SIEM ? Its Use ? ( More SIEM based questions in a small section later on same page)
25. Describe some Incident that you faced, and how you handled it ?
26. How do you Investigate a suspicious Login alert for a business user email?
27. What is difference in Credential Stuffing ? and password Spraying ? How do you detect these ?
28. Make a use-case of Password Spraying attack.
----

## Malware Anaysis

1. What types of Malware Analysis are posible ?
2. Explain Static Analysis and Dynamic Analysis of Malwares. 

----


## Compliance Audit GRC and more.

1. What s GDPR ? How does this affects you/us ? 

Hontesly I have no-clue of this branch, but questions on compliance standards , something around ISO PCI and other standards will be expected, and also updated here. Soon* . 


----

# Opinion based questions or Scenario....

These questions are to know your views, and there is usually no right or wrong answer here. It is more of a discussion to know your opinions , the way you see the problem or solve it, there is/are always more approaches to solve the problem.

1. ### Do you prefer Open-Source projects or proprietary ones? And why?

    **Preference:** I generally prefer open-source projects.

    **Reasons:**
    - **Transparency:** Open-source projects allow anyone to inspect, audit, and verify the code, leading to greater trust and security.
    - **Community Support:** A large and active community can contribute to rapid bug fixes, feature enhancements, and provide support.
    - **Flexibility:** Open-source software can be modified and customized to meet specific needs without vendor lock-in.
    - **Cost:** Open-source projects are often free to use, reducing costs for organizations and individuals.

    However, proprietary software can be preferred in cases where:
    - **Dedicated Support:** Proprietary software often comes with professional support and service level agreements.
    - **Specific Features:** Certain features or integrations might only be available in proprietary software.
    - **Regulatory Compliance:** Some industries may require software that is certified or compliant with specific regulations, which might only be available from proprietary vendors.

2. ### Geo-Blocking IP ranges is a good idea? Why or why not?

    **Pros:**
    - **Security:** Geo-blocking can prevent access from regions known for high levels of cybercrime, reducing the attack surface.
    - **Compliance:** Helps in complying with certain regulations or sanctions that restrict access from specific countries.

    **Cons:**
    - **Accessibility:** Legitimate users traveling or residing in blocked regions may be unfairly denied access.
    - **Bypass Techniques:** Attackers can use VPNs, proxies, or compromised systems within allowed regions to bypass geo-blocking.
    - **Global Business:** Companies with a global presence may need to serve customers from all regions, making geo-blocking impractical.

    **Conclusion:** Geo-blocking can be a useful security measure when implemented with consideration of its limitations and potential impacts on legitimate users. It should be part of a broader security strategy rather than a standalone solution.

3. ### Can you explain some recent security breaches or well-known attacks?

    **Example 1: SolarWinds Attack (2020)**
    - **Summary:** Attackers compromised the SolarWinds Orion software, inserting a backdoor called "Sunburst" into updates. This allowed attackers to infiltrate numerous organizations, including government agencies and Fortune 500 companies.
    - **Impact:** Sensitive data was accessed, and the attack highlighted vulnerabilities in supply chain security.
    - **Lessons:** Emphasized the need for supply chain security, robust monitoring, and incident response plans.

    **Example 2: Colonial Pipeline Ransomware Attack (2021)**
    - **Summary:** The Colonial Pipeline, a major fuel pipeline operator in the U.S., was hit by a ransomware attack, leading to operational shutdown and fuel supply disruptions.
    - **Impact:** Caused fuel shortages and highlighted the vulnerability of critical infrastructure to cyberattacks.
    - **Lessons:** Underlined the importance of cybersecurity in critical infrastructure, the need for incident response plans, and the debate on paying ransoms.

    **Example 3: Log4Shell Vulnerability (2021)**
    - **Summary:** A critical zero-day vulnerability (CVE-2021-44228) in Apache Log4j, a widely used logging library, was discovered. It allowed remote code execution, impacting numerous applications and services.
    - **Impact:** Affected millions of systems globally, prompting widespread emergency patches and updates.
    - **Lessons:** Highlighted the risks associated with third-party dependencies and the need for timely vulnerability management.

4. ### Our data is exfiltrated and encrypted in a Ransomware attack we suffered from. Should we pay to attacker to get the key or data back?

    **Considerations:**

    - **Paying the Ransom:**
      - **Pros:**
        - May quickly restore access to encrypted data.
        - Potentially less downtime and business interruption.
      - **Cons:**
        - No guarantee that attackers will provide the decryption key or that the key will work.
        - Encourages and funds criminal activity, possibly leading to more attacks.
        - Legal and ethical implications, as paying could be illegal in some jurisdictions or if the attackers are sanctioned entities.

    - **Not Paying the Ransom:**
      - **Pros:**
        - Does not support criminal enterprises.
        - Encourages the adoption of stronger security measures and incident response plans.
      - **Cons:**
        - Data may be permanently lost if backups are not available.
        - Potential longer downtime and recovery period, leading to higher operational impact.

    **Best Practices:**
    - **Preparation:** Implement robust backup and disaster recovery plans to restore data without paying the ransom.
    - **Response:** Engage with cybersecurity experts and law enforcement to navigate the incident.
    - **Prevention:** Strengthen security posture to prevent future attacks, including regular updates, employee training, and vulnerability assessments.

    **Conclusion:** Generally, it is advisable not to pay the ransom, given the ethical, legal, and practical concerns. Focus should be on preparation and prevention to mitigate the impact of ransomware attacks.


More questions based on some experience  coming here soon. As Cyber Sec Interviews are mostly for one of the roles, so follow up questions and scenarios are limited in scope. But will share some.

---

## Programming Automation Tools.

1. ### Are you good at coding? How good are you with programming?

    Yes, I am proficient in coding with strong skills in various programming languages, particularly Python. I have experience in developing, debugging, and maintaining complex applications, and I am comfortable with both scripting and object-oriented programming.

2. ### What is the choice of Language? Which one are you comfortable with?

    My preferred choice of language is Python due to its readability, extensive libraries, and versatility in various domains such as web development, data analysis, and automation. I am also comfortable with other languages like JavaScript, Bash, and SQL.

3. ### Write code to fetch IP Address from a JSON file.

    ```python
    import json

    # Sample JSON data
    json_data = '''
    {
        "devices": [
            {"name": "Device1", "ip": "192.168.1.1"},
            {"name": "Device2", "ip": "192.168.1.2"}
        ]
    }
    '''

    # Load JSON data
    data = json.loads(json_data)

    # Fetch IP addresses
    ip_addresses = [device['ip'] for device in data['devices']]
    print(ip_addresses)
    ```

4. ### Write code to fetch valid email addresses from a JSON file. Email addresses can have (., _, numbers).

    ```python
    import json
    import re

    # Sample JSON data
    json_data = '''
    {
        "users": [
            {"name": "User1", "email": "user1@example.com"},
            {"name": "User2", "email": "user.2_example@example.com"},
            {"name": "User3", "email": "invalid-email"}
        ]
    }
    '''

    # Load JSON data
    data = json.loads(json_data)

    # Regular expression for valid email addresses
    email_regex = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')

    # Fetch valid email addresses
    valid_emails = [user['email'] for user in data['users'] if email_regex.match(user['email'])]
    print(valid_emails)
    ```

5. ### Have you worked with Python Web Requests? Possibly parsing the response in the desired format.

    Yes, I have worked with Python's `requests` library to make HTTP requests and parse responses. Here is an example:

    ```python
    import requests

    # Make a GET request
    response = requests.get('https://jsonplaceholder.typicode.com/posts')

    # Parse JSON response
    posts = response.json()

    # Print the title of each post
    for post in posts:
        print(post['title'])
    ```

6. ### Write a program to do Network Packet Analysis, maybe fetch the .exe or .elf payload data from network data captured in a PCAP file.

    ```python
    import pyshark

    # Load the pcap file
    capture = pyshark.FileCapture('network_traffic.pcap')

    # Filter packets containing .exe or .elf payloads
    for packet in capture:
        if 'http' in packet and hasattr(packet.http, 'file_data'):
            file_data = packet.http.file_data
            if file_data.endswith(('.exe', '.elf')):
                print(f"Found payload: {file_data}")
    ```

7. ### Write a RegEx to filter websites / URL / URL with Queries / Email Address / IP Address / Phone Number (10-digits).

    ```python
    import re

    # Regular expressions
    regex_patterns = {
        "website": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        "url_with_queries": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:\?[-\w&=%]*)?',
        "email": r'[\w\.-]+@[\w\.-]+\.\w+',
        "ip_address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        "phone_number": r'\b\d{10}\b'
    }

    # Sample text
    text = '''
    Contact us at support@example.com or visit our website https://example.com.
    For more info, visit https://example.com/info?query=param.
    Server IP: 192.168.1.1. Call us at 1234567890.
    '''

    # Find all matches
    for key, pattern in regex_patterns.items():
        matches = re.findall(pattern, text)
        print(f"{key.capitalize()}s: {matches}")
    ```

8. ### (Bash) - replace all occurrences of string - string_1 with string_1_1 in a text file.

    ```bash
    # Replace all occurrences of 'string_1' with 'string_1_1' in 'file.txt'
    sed -i 's/string_1/string_1_1/g' file.txt
    ```

9. ### You have a source file of a program and want to maintain it as such - every parenthesis open and close have exactly 1 whitespace after and before, where white space is not present add it, where extra white-space, remove extra and keep one. How do you programmatically solve this?

    ```python
    import re

    # Read the source file
    with open('source_file.py', 'r') as file:
        content = file.read()

    # Add exactly one whitespace around parentheses
    content = re.sub(r'\s*\(\s*', ' ( ', content)
    content = re.sub(r'\s*\)\s*', ' ) ', content)

    # Remove extra whitespaces
    content = re.sub(r'\s+', ' ', content)

    # Write the modified content back to the file
    with open('source_file.py', 'w') as file:
        file.write(content)
    ```

### More questions based on some projects and required coming here soon.

---

## Random Questions

These are totally random questions, makes less sense to judge on ( personal Opinion* ), but just for the sake of interaction sometimes you can hear these. I hope people dont represent the *Illuminati*  view here, and be moderate or balanced in answering. 

1. ### Security is a fast-moving field. How do you keep yourself updated?

    To keep updated in the fast-moving field of security, I:
    - Regularly read industry news from sources like Krebs on Security, Dark Reading, and SecurityWeek.
    - Follow cybersecurity experts and organizations on social media.
    - Participate in online forums and communities such as Reddit's /r/netsec and Stack Exchange.
    - Attend webinars, conferences, and workshops.
    - Enroll in ongoing education and certification courses.
    - Subscribe to threat intelligence feeds and newsletters.

2. ### What is your understanding of Insider Threats? How to detect them?

    **Insider threats** are security risks that originate from within the organization. These can be current or former employees, contractors, or business partners who have access to the organization's network, systems, or data.

    **Detection Methods:**
    - Monitoring user behavior for anomalies.
    - Implementing strict access controls and least privilege policies.
    - Using Data Loss Prevention (DLP) tools.
    - Conducting regular audits and reviews of access logs.
    - Encouraging a culture of security awareness among employees.

3. ### Social Media websites such as Instagram and LinkedIn are ok to use at the workplace? Why or why not?

    **Pros:**
    - LinkedIn can be useful for networking, recruitment, and professional development.
    - Social media can serve as a marketing tool and enhance the company's online presence.

    **Cons:**
    - Potential for decreased productivity if used for personal purposes.
    - Risk of data leakage or exposure to social engineering attacks.
    - Increased vulnerability to phishing and malware.

    The appropriateness of using social media at work depends on the company's policy, the role of the employee, and the potential security risks.

4. ### Is iOS more secure compared to Android?

    **iOS:**
    - Generally considered more secure due to Apple's stringent app review process and closed ecosystem.
    - Regular updates and patches are pushed directly to users.
    - Stronger default privacy settings and data encryption.

    **Android:**
    - Open-source nature and broader device manufacturer base lead to fragmentation and inconsistent security updates.
    - Users have more flexibility but also more exposure to risks from third-party app stores and customizations.

    While iOS is often deemed more secure, both platforms can be secure if users follow best practices and maintain updated systems.

5. ### Are you a Linux user or Windows? Which is more secure? Why do you think so?

    **Linux:**
    - Preferred by many for its open-source nature and customization options.
    - Often considered more secure due to its Unix-based architecture and user permission management.
    - Less targeted by malware compared to Windows, but not immune.

    **Windows:**
    - Widely used, making it a more common target for attackers.
    - Regular updates and security features like Windows Defender improve its security.
    - User-friendly and widely supported by applications.

    Security largely depends on the user's knowledge, how the system is configured, and the security practices followed rather than the operating system itself.

6. ### What is the Dark Web, and how is it different compared to the Deep Web?

    **Deep Web:**
    - Refers to parts of the internet not indexed by standard search engines.
    - Includes private databases, academic journals, internal company websites, and other restricted-access content.
    - Not inherently malicious or illegal.

    **Dark Web:**
    - A subset of the deep web intentionally hidden and accessible only through specific software such as Tor.
    - Often associated with illegal activities, including marketplaces for illicit goods, hacking services, and forums.
    - Provides anonymity to users, which can be used for both legitimate and illegal purposes.

    The key difference is that the deep web encompasses all unindexed web content, while the dark web specifically refers to hidden, often anonymized sections typically used for activities requiring privacy.



