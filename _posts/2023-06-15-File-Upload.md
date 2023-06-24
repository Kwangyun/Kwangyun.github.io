# File Upload Vulnerabiltiy Report

## Table of Contents
- [**Outline**](#section-0)
- [**Vulnerability Explanation**](#section-1)
- [ **Proof of Concept - Establishing a  Reverse Shell**](#section-2)
- [ **Source Code Analysis**](#section-3)
- [**Mitigating File Upload Vulnerability**](#section-4)

## Outline {#section-0}
The goal of this write-up is to document and demonstrate File Upload vulnerabilities against the Damn Vulnerable Web Application (DVWA). The objective of this attack was to gain a Remote Code Execution (RCE) as `www-data`. This report mocks a penetration testing report and a debriefing situation to a client. 

## Vulnerabiltiy Explanation {#section-1}

A file upload vulnerability is a security flaw that allows an attacker to upload and execute malicious files on a target system. This occurs when users are allowed to upload files to its filesystem without sufficiently validating name, type, contents, or size. Failing to properly enforce restrictions on these could lead to server-side codes to be executed such as a web shell or remote code executions, granting attackers full control over the server. If file sizes are not properly checked, it could lead to Denial of Service (DOS), flooding limited memory space.

The base CVSS was calculated upon the following metrics.  
| Information | Explanation                         |
|-------------|-------------------------------------|
| Name        | File Upload Vulnerability           |
| Severity    | High                                |
| CVSS        | 8.1                                 |
| Path        | http://127.0.0.1/vulnerabilities/fi |

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


## Proof of Concept {#section-2}
For the Proof of Concept (POC), the tester uploaded a `php-reverse-shell.php` created by [Ivan-sincek](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php) to the file upload section. By visiting the uploads directory, the tester confirmed a successful  reverse shell. Below are the steps taken.
First, the tester modified the IP and Port of the `php-reverse-shell.php` to the testers IP and Port.
![](/assets/upload/change.png)  
The script was uploaded successfully.
![](/assets/upload/success.png)  

Next, the tester created a  net cat listener to catch the reverse shell.
```bash
nc -nlvp 5555 
``` 
The tester appended the URL to initiate the script.
```bash
../../hackable/uploads/php-reverse-shell.php
```

 The tester gained an interactive reverse shell as demonstrated below.
![](/assets/upload/REV.gif)

## Source Code Analysis {#section-3}
### Security-Low-Level
![](/assets/upload/easy.png)  
In the `Security-Low-Level module`, there are zero security measures in place to check file extension and other file properties such as size or content type. 
The above source code accepts the file from user, saves it in a temporary folder and checks whether the file could be transferred to upload folder. Without any prevention mechanism in place, the attacker uploaded a PHP file and obtained a reverse shell with ease.

### Security-Medium-Level
![](/assets/upload/medium.png)  
In the `Security-Medium-Level module`, there are minimal security measures to validate user upload. First, the code checks the content type of the uploaded file. That is, only files with content type `image/jpeg` and `image/png` are allowed. In addition, if the size of the file is greater than [100 kB], uploads are restricted.

The problem arised when the value of this header was implicitly trusted by the server. There were no further validation to check whether the contents of the file actually matched the supposed media type. Thus, this defense mechanism was bypassed using Burp Suite. Burp Suite is an integrated platform/graphical tool for performing security testing of web applications. First, the tester intercepted the upload request using Burp Suite.
![](/assets/upload/content.png)  
The tester modified the content type from  `application/x-php`to `image/jpeg`
![](/assets/upload/type.png)  
The tester successfully uploaded the reverse shell script.
![](/assets/upload/success.png)  

### Security-High-Level
![](/assets/upload/high.png)  

 In the `Security-High-Level module`, the code ensures that the file extension matches a certain format. However, the tester bypassed this defense mechanism by making use of Burp Suite alongside local File Inclusion Vulnerability (LFI) and Path Traversal attacks.
First, the code retrieves the original name of the uploaded file.
 ```bash
  `$uploaded_name = $_FILES['uploaded']['name'];`
 ```
Next, it extracts the file extension from the name and checks if the file extension is either `jpg,` `jpeg`, or `png`. The `strtolower()` function converts the extension to lowercase for case-insensitive comparison.
```bash
$uploaded_ext = substr($uploaded_name, strrpos($uploaded_name, '.') + 1);
(strtolower($uploaded_ext) == "jpg" || strtolower($uploaded_ext) == "jpeg" || strtolower($uploaded_ext) == "png")
```
The tester intercepted the upload request and added `.jpeg` to the file extension and changed the content type to `image/jpeg`. Next the tester also added a `GIF89`. Adding the `GIF89a` as the content type when uploading a non-image file is a common technique used to bypass file upload restrictions. This technique takes advantage  filtering mechanisms that may only check the file extension or content type to determine if a file is an image. Since gif is an extension of the image file, this method was succeessful.
![](/assets/upload/high1.png)  
To execute the JPEG file, the tester made use of the Local File Inclusion (LFI) vulnerability to visit the URL
```bash
http://127.0.0.1/vulnerabilities/fi/?page=file:///../../../..//var/www/html/hackable/uploads/php-reverse-shell.jpeg
```
The tester gained a reverse shell again.
![](/assets/upload/REV1.gif)  

This attack is possible because LFI does not check the file extension. Instead, it directly executes the code present inside the file.
## Mitigating File Uplaod Vulnerabiltiy  {#section-4}  



### Reference: 
[GrootBoan](https://security.grootboan.com/) and
[Offensive Security](https://www.offsec.com/metasploit-unleashed/file-inclusion-vulnerabilities/) 