## CVSS
## Table of Contents
- [**Definition**](#section-0)
- [**Discussing The Base Score Metrics**](#section-1)

## Definition
Common Vulnerabiltiy Scoring System (CVSS) is a framework used to assess the severity and impact of security vulnerabiltiy.
The CVSS assigns a numerical value from 0 to 10 with higher scores indicating a more severe vulnerabiltiy.
The CVSS is based on various metrics such as `exploitability of the vulneraability`, `potential impact on confidentiality` 
and `availability of the affected system`.\
Different organizations might have there own template for calculating CVSS but the National Institute of Standards and Technology (NIST)'s National Vulnerabiltiy Databse (NVD)
has a standard CVSS calculator which could be found [here](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) \

## Discussing The Base Score Metrics
There are mainly two sub categories in the `Base Score Metrics`: `Exploitability Metrics` and `Impact Metrics` 
Under the two sub categories there are different metrices which will be explained below.
### Attack Vector  (AV): 
This measures the way an attacker can exploit a vulnerability and gain access to a target system. Simply put, the more remote the attacker can exploit a system the higher the value.
Network (N): This means the vulnerability can be exploited remotely over a network connection.  
Adjacent Network (A): This signifies that the attacker needs to have access to the same network.   
Local (L): This means the attacker requires local acces i.e physical access.  
In this case we can say that **(N)** contributes to a higher CVSS score.    
### Attack Complexity (AC)
This measures the level of expertise, resources, and conditions needed for an attacker to successfully carry out an exploit.
Low (L): This means that exploiting the vulnerability is straightforward and requires minimal or no specialized knowledge or resources such as public exploit tools.
High (H): This means that exploiting the vulnerability is highly complex and typically requires advanced skills, extensive knowledge, or significant resources.
In  this case **(L)** would contribute to a higher CVSS score. 
### Privileges Required (PR) 
This measures the level of privilege required for the attacker to exploit the vulnerability.  
None (N): No privileges are required to exploit the vulnerability.  
Low (L): The attacker requires some privileges.  
High (H): The attacker requires elevated privileges, such as administrative or root access.  
In this case  **(N)** contributes to a higher CVSS score.  
### User Interaction (UI) 
The UI metric evaluates whether a successful exploitation of a vulnerability requires interaction from a user or if it can be accomplished without any user involvement.
None (N): The vulnerability can be exploited without any user interaction. This means that an attacker can exploit the vulnerability remotely or automatically without relying on user actions.
Required (R): The vulnerability can only be exploited if a user interacts with the system or application.
In this case  **(N)** would contribute to a higher CVSS score.
### Scope (S)
The scope metrics has been added to the new CVSS 3.0. It evaluates whether an exploit of a software impacts other system.
Unchanged(S:U): An exploit can only affect the specific system.
Changed(S:C) An exploit can affect other systems.
In this case **(S:C)** would contribute to a higher CVSS score. 
### Confidentiality Impact (C)
This assesses the potential impact of a vulnerability on the confidentiality of information.
None (N): The vulnerability does not have any impact on the confidentiality of information.
Low (L): The vulnerability may result in a limited impact on the confidentiality of information.
High (H): The vulnerability has a significant impact on the confidentiality of information. 
In this case **(H)** would contribute to a higher CVSS score.  
### Integrity Impact (I)
This assesses the potential impact of a vulnerability on the integrity of information or data.
None (N): It means that even if the vulnerability is successfully exploited, it will not result in any unauthorized modification or tampering of data.
Low (L): The vulnerability may result in a limited impact on the integrity of information.  
High (H): The vulnerability has a significant impact on the integrity of information.  
In this case **(H)** would contribute to a higher CVSS score.  

### Availability Impact (A)
This assesses  evaluates the degree to which the exploitation of a vulnerability can disrupt or prevent the normal functioning or availability of a system, 
None (N): The vulnerability does not have any impact on the availability of the system or resource.     
Low (L): The vulnerability may result in a limited impact on the availability of the system or resource.  
High (H): The vulnerability has a significant impact on the availability of the system or resource.  
In this case **(H)** would contribute to a higher CVSS score.  


Reference: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator