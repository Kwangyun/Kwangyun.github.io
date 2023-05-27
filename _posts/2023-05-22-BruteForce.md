# Brute forcing DVWA login page


## Outline

The goal of this write-up is to document a brute force attack performed against the login system of DVWA(Dam Vulernable Web Application). The objective of this attack was to gain unauthorized admin access through brute forcing password against the `admin` account. This was conducted as a group-study project for Groot Security. \
The writeup discusses the following content:

1. **Vulnerabiltiy Explanation**
2. **Proof of Concept - Making use of Hydra and Burpsuite**
3. **Mitigating Brute Force Attacks**

| Information | Explanation                                                                      |
|-------------|----------------------------------------------------------------------------------|
| Name        | User Authentication Brute Force                                                  |
| Severity    | High                                                                             |
| CVSS        | 8.1                                                                              |
| Path        | http://127.0.0.1/vulnerabilities/brute/?username=admin&password=1234&Login=Login |

## Vulnerabiltiy Explanation
A brute force attack is systematically trying out all possible combinations of password or username into a system until a valid credentials is found.
The purpose of a brute force attack is to gain unauthorized access into a system. This could not only lead to loss of sensetive data, but also a possible privilege escalation
for the attacker. If the breached credentials has admin level access, this could signify an entire take over of a system.

The DVWA /vulnerabilities/brute URL is vulnerable to user authentication brute force attack, as it does not have security measures in place.

We were able to sucessfully attain the password for the 'admin' account and gain access to the 'Protected Admin Area' 

## Proof of Concept
For POC, we will make use of the Hydra tool for brute forcing the following login page.
![이미지](/assets/loginpage.png)
In order to use Hydra, we figure out that the login is using a http-get-form. We also know that the user is 'admin'. We will make use of the famous rockyou.txt password list for our
brute force attack.
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect."
``` 
We can see that Hyrda was able to give multiple passwords for the account admin.
![이미지](/assets/sucess.png)

Using one of its credentials, `password` we are able to sucessfully login to the `protected Admin Area`
![이미지](/assets/logedin.png)

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
![이미지](/assets/result.png)

## Mitigating Brute Force Attacks, its benefits and downside
The brute force attack was mainly possible due to lack of secure coding. 
There are various ways to mitigate brute force attacks.
0. Strong passwords without password reuse
Creating a strong password with multiple combination of special character and a minimum length of 15 could prevent brute force dictionary attacks. Moreover not reusing the same password makes attacks unsucessful from leaked credentials.
1. MFA (Multi Factored Authentication)
Multi Factored Authentication is an authentication method that requires the user to provide two or more verfication method. 
This includes methods such as password + fingerprint(biometric) or password + pin code from the user. The most common MFA used is 2FA (2 Factored Authentication)
Although MFA provides maximum security, different types of MFA methods could be bypassed via social engineering techniques such as phishing attacks, Response  Manipulation, pass the cookie attacks and etc. 
Moreover, heavy MFA may also reduce user usabiltiy if MFA is required everytime upon login.
2. Account Lockout
Another method is account lockouts after specific time frame. The below image shows the php code for the `impossible level` DVWA .
![이미지](/assets/lockout.png)
It shows that if the user attemps more than 3 wrong passwords, the account is lockedout which prevents brute forcing.
Account Lockouts methods could be vulnerable to password-spray attacks also known as low-and-slow methods where the attacker attempts a common password over a long span of time after each attempt.
Moreover another downside of this strict lockout policy is that it could lead to intentional account lockouts from attackers which may hinder user usability and accessibility.
3. Captcha 
Captcha is a program or system intended to distinguish human from machine input. This can be useful from distinguishing a brute force attack (machine). The below image is an example of captcha, demonstrating the need for human interaction.
![이미지](/assets/cptcha.png)

In conclusion, although it may be tedious for an user to go through all these security measures, it is important to combine the mentioned methods to mitigate brute force attack as much as possible.

References:
https://security.grootboan.com/follow-along/undefined/0-dvwa/reference-writeup
https://socradar.io/mfa-bypass-techniques-how-does-it-work/