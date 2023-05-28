
# Brute Forcing DVWA Login Page


## Outline

The goal of this write-up is to document a brute force attack performed against the login system of DVWA (Damn Vulnerable Web Application). The objective of this attack was to gain unauthorized admin access through brute-forcing passwords against the `admin` account. This was conducted as a individual study project hosted by [Grootboan Security](https://security.grootboan.com/). \
The writeup discusses the following content:

1. **Vulnerabiltiy Explanation**
2. **Proof of Concept - Making use of Hydra and Burpsuite**
3. **Developing a Simple Python Tool**
4. **Mitigating Brute Force Attacks**

| Information | Explanation                                                                      |
|-------------|----------------------------------------------------------------------------------|
| Name        | User Authentication Brute Force                                                  |
| Severity    | High                                                                             |
| CVSS        | 8.1                                                                              |
| Path        | http://127.0.0.1/vulnerabilities/brute/?username=admin&password=1234&Login=Login |

## Vulnerabiltiy Explanation
A brute force attack systematically tries out all possible combinations of passwords or usernames on a system until valid credentials are found. The purpose of a brute force attack is to gain unauthorized access to a system. This not only risks the loss of sensitive data but also opens the possibility of privilege escalation for the attacker. If the compromised credentials have admin-level access, it could result in a complete takeover of the system.

The DVWA /vulnerabilities/brute URL is vulnerable to user authentication brute force attacks, as it lacks adequate security measures.

We were able to successfully obtain the password for the `admin` account and gain access to the `Protected Admin Area` 

## Proof of Concept
For POC, we will make use of the Hydra tool for brute forcing the following login page.
![](/assets/hydra.gif)
In order to use Hydra, we figure out that the login is using a http-get-form. We also know that the user is `admin`. We will make use of the famous rockyou.txt password list for our
brute force attack.
```bash
 hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-get-form '/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\:PHPSESSID=9sosvqo963thpd5jqf9mum3f41; security=low:F=Username and/or password incorrect'
``` 

Using the credential, `password` we are able to sucessfully login to the `protected Admin Area`
![](/assets/success.gif)

Now we will try using burpsuite to conduct the same brute force attack.
![이미지](/assets/burp.png)

First we intercept the login request using burpsuite. We then send the request to intruder to select the password field. We pick sniper mode and choose a password wordlist
from the following directory
```bash
/usr/share/wordlist/seclists/Passwords/Common-Credentials/500-worst-password.txt
```
![이미지](/assets/payload.png)

Upon conducting the brute force attack, we find that `password` has a length that is different from the other passwords. Looking at the response we see that we were sucessfully
able to login  into the `protected area admin` 
![](/assets/burpresult.gif)
## Developing Python Script
To automate the attack and practice programing in python, we have created simple python script that automates the attack.
The python script can be found in the following link.
[Brute Force script](https://github.com/Kwangyun/Web-Automation-Tools) \
We can see that upon running the code, we were able to sucessfully brute force `password` for user `admin`
![](/assets/Test.gif)

## Mitigating Brute Force Attacks, its benefits and downside
The brute force attack was mainly possible due to lack of secure coding. 
There are various ways to mitigate brute force attacks. \
**Strong passwords without password reuse**\
Creating a strong password with multiple combinations of special characters and a minimum length of at least 15 characters can help prevent brute force and dictionary attacks. Additionally, avoiding password reuse across different accounts or platforms makes it more difficult for attackers to succeed using leaked credentials.\
**MFA (Multi Factored Authentication)**\
Multi-Factor Authentication is an authentication method that requires the user to provide two or more verification methods. This includes methods such as password + fingerprint (biometric) or password + PIN code. The most common form of Multi-Factor Authentication is 2FA (Two-Factor Authentication). 

Although MFA provides maximum security, different types of MFA methods could be bypassed through social engineering techniques such as phishing attacks, response manipulation, pass-the-cookie attacks, and more. Additionally, implementing heavy MFA may also reduce user usability if MFA is required every time during login. Moreover, heavy MFA may also reduce user usabiltiy if MFA is required everytime upon login. 
**Account Lockout**\
Another method is account lockouts after specific time frame. The below image shows the php code for the `impossible level` DVWA .
![이미지](/assets/lockout.png)
It is common for systems to implement an account lockout policy where, if a user attempts more than three wrong passwords, the account gets locked out. This mechanism helps prevent brute force attacks. However, account lockout methods can be vulnerable to password-spray attacks, also known as low-and-slow methods, where the attacker attempts a common password over a long span of time after each attempt. 

Furthermore, a strict lockout policy has another downside: it can lead to intentional account lockouts by attackers. This intentional lockout can hinder user usability and accessibility.
**Captcha**\
Captcha is a program or system intended to distinguish human from machine input. This can be useful from distinguishing a brute force attack (machine). The below image is an example of captcha, demonstrating the need for human interaction. 
![이미지](/assets/captcha.png)
## Conclusion
In conclusion, while implementing various security measures can be demanding for users, it is imperative to understand the significance of combining these methods to fortify our defenses against brute force attacks. By embracing a multi-layered approach to authentication, including strong passwords, multi-factor authentication, and account lockout policies, we demonstrate a proactive stance in safeguarding our sensitive information. 

References: \
[Grootboan Security](https://security.grootboan.com/follow-along/undefined/0-dvwa/reference-writeup)\
[MFA BYPASS](https://socradar.io/mfa-bypass-techniques-how-does-it-work/)
