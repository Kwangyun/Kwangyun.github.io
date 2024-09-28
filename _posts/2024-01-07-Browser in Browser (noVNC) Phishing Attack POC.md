## Table of Contents

- [**Outline**](#section-0)
- [**Domain and Server Setup**](#section-1)
- [**Cloning and Setting Up NoPhish**](#section-2)
- [**DNS and HTTPS Configuration**](#section-3)
- [**Launching the Phishing Attack**](#section-4)
- [**Accessing the Admin Panel**](#section-5)
- [**Conclusion**](#section-6)




## Outline  {#section-0}


This document will illustrates a POC of executing a Browser in Browser (BiB) novnc attack. This attack bypasses MFA by simulating legitimate login prompts from trusted services (e.g., Microsoft Login page). 

<video width="640" height="480" controls>
  <source src="/assets/AV/BIB.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

# Domain and Server Setup   {#section-1}
Purchase the necessary domain and server infrastructure.

1. **Visit Namecheap**  
   Navigate to [Namecheap](https://www.namecheap.com) to purchase a domain

2. **Search for a domain**  
   Use Namecheap’s domain search function to find and purchase a domain that looks convincing. For this example, the tester has purchased `authenticate3.com`.


3. **Register the domain**  
   Complete the registration process for `authenticate3.com`.

Register the domain
Complete the registration process for authenticate3.com.

### Setting Up a Server on Linode

1. **Visit Linode**  
   Go to [Linode](https://www.linode.com) and sign up for an account 

2. **Create a new Linode instance**  
    Create a new virtual private server (VPS) instance. 

3. **Select a Linux distribution**  
   For this attack, choose **Kali Linux** as the OS for the Linode instance. Complete the setup and boot up your server.

4. **Obtain the server IP address**  
   Once the server is running, note down the **IP address** assigned to Linode instance, e.g., `172.xx.xx.xx`.

## Cloning and Setting Up NoPhish {#section-2}

Next, we will clone the **NoPhish** tool from GitHub and set it up on our Linode server.


3. **Cloning the NoPhish repository**   
For phishing attacks like Browser in Browser, tools like **NoPhish** can be used to create convincing phishing pages. Ensure that the necessary dependencies (e.g., Docker, Git) are installed to avoid runtime issues.

The phishing page should be customized to resemble the target's legitimate login window, using a tool that supports URL customization and redirection techniques. This includes specifying the URL that users will see and setting up any necessary components, such as HTTPS encryption, to avoid detection

## DNS and HTTPS Configuration {#section-3}

To enhance the credibility of your phishing site the tester configured **DNS** settings appropriately. This involves associating purchased domain with the server's IP address using DNS providers like Cloudflare. With Cloudflare’s DNS management, A and CNAME records can be adjusted to point to your server.

In addition, HTTPS encryption should be enabled through services like Cloudflare’s **SSL/TLS** configuration to give the phishing page the appearance of legitimacy. 