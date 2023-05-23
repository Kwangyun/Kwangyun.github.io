# Brute forcing DVWA login page


## Outline

The goal of this write-up is to document a brute force attack performed against the login system of DVWA(Dam Vulernable Web Application). The objective of this attack was to gain unauthorized admin access by brute forcing password against the 'admin' account. This was conducted as a group-study project for Groot Security. \
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

## Mitigating Brute Force Attacks
The brute force attack was mainly possible due to lack of secure coding. 
There are various ways to mitigate brute force attacks.
1. MFA (Multi Factored Authentication)
2. Account Lockout
![이미지](/assets/lockout.png)
The php source code shows that if the user attemps more than 3 wrong passwords, the account is lockedout.
3. Captcha 