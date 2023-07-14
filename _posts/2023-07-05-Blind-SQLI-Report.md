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
```php
$getid = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors

    // Get results
    $num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
    if( $num > 0 ) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    }
    else {
        // User wasn't found, so the page wasn't!
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }


```
In the `Security Low Level Module`, the provided code snippet exhibits a blind SQL injection vulnerability due to the direct concatenation of the user input `($id)` into the SQL query. The code attempts to suppress SQL query error outputs. However, this does not mitigate the underlying vulnerability introduced by the direct concatenation of the `$id` variable into the SQL query. An attacker can manipulate the value of the 'id' parameter in the URL to inject arbitrary SQL code, potentially altering the query's behavior or extracting sensitive data from the database.

To address this vulnerability, the developers should use prepared statements or parameterized queries to handle user input securely. 
### Security-Medium-Level
```php
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $id = $_POST[ 'id' ];
    $id = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $id ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Check database
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors

    // Get results
    $num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
    if( $num > 0 ) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    }
    else {
        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    } 
```
In the `Security Medium Level Module`, the code takes input from the user through the `$_POST['id']` parameter. However, this lacks proper input sanitization to protect against SQL injection attacks.

To mitigate this vulnerability, the developers attempt to sanitize the input using `mysqli_real_escape_string()`. However, the usage of this function does not tackle the vulnerable `$id` parameter. Thus, the code fails to use prepared statements or parameterized queries, which are more secure approaches for handling user input in SQL queries.

The vulnerable code directly inserts the sanitized `$id` value into the SQL query without appropriate parameterization. This allows an attacker to manipulate the value of the id parameter and potentially execute unauthorized SQL statements.


### Security-High-Level
```php
$getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors

    // Get results
    $num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
    if( $num > 0 ) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    }
    else {
        // Might sleep a random amount
        if( rand( 0, 5 ) == 3 ) {
            sleep( rand( 2, 4 ) );
        }

```
In the `Security-High-Level module`, an additional security measure has been implemented by adding a `LIMIT 1;` statement to the SQL query after the `user_id = '$id'` condition. This measure aims to restrict the output of the SQL database to only one record, thereby mitigating the impact of sophisticated attacks such as the UNION-based attack.

However,  this method alone was not sufficient to prevent automated tools such as SQLmap as the `user_id` field itself is inherently vulnerable to SQL injection. Although the user might not be able to directly see the output when manually injecting SQL queries, SQLmap was still able to exploit this state. Therfore, it is of prime importance to tackle the root cause of the problem rather than limiting what type of error message is shown in the front-end of the web page.

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