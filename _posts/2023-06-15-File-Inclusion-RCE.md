# CSRF Vulnerabiltiy Report

## Table of Contents
- [**Outline**](#section-0)
- [**Vulnerabiltiy Explanation**](#section-1)
- [ **Proof of Concept - Simulating a Phishing Attack**](#section-2)
- [ **Analyzing Source Code -**](#section-3)
- [**Mitigating CSRF Attacks**](#section-4)

## Outline {#section-0}
The goal of this write-up is to document and demonstrate CSRF (Cross Site Request Forgery) attacks performed  against the  Damn Vulnerable Web Application (DVWA). The objective of this attack was to change the password of the `admin` account through CSRF attack.This report mocks a penetration testing report and a debriefing situation to a client.

## Vulnerabiltiy Explanation {#section-1}
CSRF is an attack where the attacker causes the victim user to carry out an action unintentionally while that user is authenticated. This can disrupt normal user expereince, lead to data manipulation, deletion, and at times account takeovers. Depending on the account privilege, an attack could lead to a full control over a application system. CSRF attacks often involve social engineering techniques such as tricking the user to click on a malicious link. There are several prerequisites for an CSRF attack to be successful. The user has to be already logged into the application using cookie based sessions without proper CSRF defence in place. The user has to be tricked to conduct some action such as clicking on a malicious link. 

| Information | Explanation                                                                      |
|-------------|----------------------------------------------------------------------------------|
| Name        | CSRF                                                                             |
| Severity    | High                                                                             |
| CVSS        | 8.3                                                                              |
| Path        | http://127.0.0.1/vulnerabilities/exec/



The base CVSS was calculated upon the following metrics.  

| Base Metrics               | Explanations                                                                                             |
|----------------------------|----------------------------------------------------------------------------------------------------------|
| Attack Vector (AV)         | Network(N) The vulnerability can be exploited remotely over a network connection.                        |
| Attack Complexity (AC)     | Low (L) The vulnerability is straightforward and requires minimal or no special knowledge.               |
| Privilege Required (PR)    | Low (L) The attack requires some privilege. The user has to login to DVWA webpage to conduct the exploit |
| User Intercation (UI)      | Required (R) The vulnerability needs user interaction.                                                    |
| Scope (S)                  | Unchanged(S:U) An exploit can only affect the specific system                                            |
| Confidentiality Impact (C) | Medium (M) The vulnerability has medium impact on  the confidentiality of information.                   |
| Integrity Impact (I)       | High (H) The vulnerability has a signigicant impact on the integrity of the information                  |
| Availability Impact (A)    | High (H) The vulnerability has a significant impact on the availability of the system or resource.       |

![](/assets/lfi/suggestive.png) 
## Proof of Concept {#section-2}
**DISCLAIMER**
1) suggestive. of file inclusion vulnerability (Pic)
2) php, test ../../../etc/passwd  (TEST)
3) identified web tech as php, we canm plat./poison log file in an attemp to include native code execution on the target machine.
. ../../../../../../../../../var/www/html/index.php Confirm we have log poisioning 





#### Creating a Phishing Email


## Source Code Analysis {#section-3}

 



## Mitigating CSRF Attacks {#section-4}  


#### Ask password again when conducting important tasks.   

#### Same Site Cookie.      


### Common flaws in CSRF token validation
1. Change the request method from from `POST` to `GET` to bypass validation.
2. Removing the entire parameter containing the token to bypass validationtion.
3. CSRF token is not tied to the user session. The attacker can log in to the application using their own account, obtain a valid token.

### Reference: 
[PortSwigger](https://portswigger.net/web-security/csrf)