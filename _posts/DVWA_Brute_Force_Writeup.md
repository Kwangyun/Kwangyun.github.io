# 제목 
Brute forcing DVWA login page

## Outline

The goal of this write-up is to document a brute force attack performed against the login system of DVWA(Dam Vulernable Web Application). The objective of this attack was to gain unauthorized admin access by brute forcing password against the 'admin' account. This was conducted as a group-study project for Groot Security. \
The writ-up discuess the following content:
1. ***Vulnerabiltiy Explanation***
2. ***Proof of Concept - Making use of Hydra and Burpsuite ***
3. ***Preventing Brute Force Attacks ***

| Information | Explanation                                                                      |
|-------------|----------------------------------------------------------------------------------|
| Name        | User Authentication Brute Force                                                  |
| Severity    | High                                                                             |
| CVSS        | 8.1                                                                              |
| Path        | http://127.0.0.1/vulnerabilities/brute/?username=admin&password=1234&Login=Login |

## Vulnerabiltiy Explanation
A brute force attack is systematically trying out all possible combinations of password or username into a system until  valid credentials are found.
The purpose of a brute force attack is to gain unauthorized access into a system. This could not only lead to loss of sensetive data but also privilege escalation
from the attacker. 