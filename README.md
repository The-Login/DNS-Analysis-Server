# DNS Analysis Server
Tools to assess DNS security.  
*This is an updated and more generic version of the [DNS Reset Checker](https://github.com/The-Login/DNS-Reset-Checker).*
## Background
### DNS security?  
The DNS (Domain Name System) is a central part of the Internet and allows us to, for example, resolve domain names like "google.com" into IP addresses like "142.250.180.206".  
**But what happens, if this DNS name resolution is vulnerable?**  
In this case, an attacker can manipulate the mapping between domain names and associated data. All of a sudden "google.com" could be pointing to "13.33.33.37" instead of Google's actual IP address.  
![BLOGPOST-Poisoned DNS (1)](https://user-images.githubusercontent.com/84237895/188393745-80f199f9-ee7f-419d-9969-41dc18d094ec.png)  
The consequences of such DNS vulnerabilities range from bypassing e-mail spam protections to compromising entire systems. For example, in some cases it's possible to take over a **fully patched** WordPress instance "just" by manipulating the DNS resolution.  
Now, to check for vulnerabilities in the DNS name resolution, the DNS Analysis Server comes into play.

*A more in-depth look at DNS security and the inner workings of the DNS Analysis Server can be found [here](https://sec-consult.com/blog/detail/forgot-password-taking-over-user-accounts-kaminsky-style/) and [here](https://sec-consult.com/blog/detail/melting-the-dns-iceberg-taking-over-your-infrastructure-kaminsky-style/).*

## Requirements and Installation
For a complete setup of the DNS Analysis Server the following components are required:
* A server (e.g. AWS EC2)
* A domain (you must be able to set your server as authoritative name server of this domain)
* docker
* docker compose
* A browser

The installation requires the following steps to be done:
1. Set the server as the authoritative DNS server of your domain (use "ns1" and "ns2" as name server names)
2. Make sure your firewall settings allow DNS traffic to reach the server
3. On the server: ```git clone https://github.com/The-Login/DNS-Analysis-Server```
4. On the server: ```sudo ./start.sh [your domain] [server ip address]``` (e.g. ```sudo ./start.sh analysis.example 203.0.113.37```)

With these steps done, the analysis server should be running on your server and receive DNS queries for the specified domain.  
To confirm this the following command can be used:
```dig 9999999999.[your domain]```  
This should return the IP address of the server.


## Usage
### Server's running, now what?
With a working analysis server, a general testing procedure can be followed:
1. Trigger a DNS resolution of a domain with the following format: ```VVMMIIIIII.[your domain]``` (e.g. 0100000001.analysis.example)
    - V: Decimal number for versioning
    - M: Decimal number for the analysis method to use
    - I: Decimal number for the **unique** identifier of the web application (one identifier per web app)
2. On the server use ```sudo ./logs.sh``` to see which analysis methods were already tested
3. If a specific analysis method is missing, trigger another DNS resolution and specify the analysis method to test (e.g. 01**02**000001.analysis.example). Goto step 2
4. Download the file ```data/dns_log.txt```
5. Fire up the ```log_analyzer.html``` in a browser and select the ```dns_log.txt``` file to start analyzing.

So, what could a more specific testing procedure look like?  
For example, for testing e-mail servers, the process is summarized in the below image:
![BLOGPOST-Analyzing the DNS resolution (1)](https://user-images.githubusercontent.com/84237895/188394975-db02bb29-faff-4417-8300-7357825e033f.png)  
Furthermore, to check for DNS vulnerabilities in web applications, the below steps can be followed:  
1. Register on a web application with an e-mail address of the following format: ```test@VVMMIIIIII.[your domain]``` (e.g. test@0100000001.analysis.example)
    - V: Decimal number for versioning
    - M: Decimal number for the analysis method to use
    - I: Decimal number for the **unique** identifier of the web application (one identifier per web app)
2. On the server use ```sudo ./logs.sh``` to see which analysis methods were already tested
3. If a specific analysis method is missing, trigger another DNS resolution (via registration) and specify the analysis method to test (e.g. test@01**02**000001.analysis.example). Goto step 2
4. Download the file ```data/dns_log.txt```
5. Fire up the ```log_analyzer.html``` in a browser and select the ```dns_log.txt``` file to start analyzing. (Add ```#no-plots``` for faster loading times)  

However, you're not restricted to just testing e-mail servers and web applications! Since **lots** of things are using the DNS, your creativity is the limit!

### What is actually happening? Why do I need to trigger a DNS resolution? What's the server for?

Let's go to through the general testing procedure again:  
As already described, the whole process starts with a trigger of a DNS resolution. For example, your special e-mail address (e.g. test@0100000001.analysis.example) is used to register on the web application with identifier "000001". This is done because web applications often send registration e-mails to new users. The  web application sending an e-mail initiates a DNS name resolution to your authoritative name server (analysis server), since you entered your analysis domain as e-mail domain. This DNS name resolution can now be analyzed and actively used to test one or more DNS attack requirements via the various analysis methods. This is done via a DNS proxy ([DNS-Analysis-Server/dns_proxy.py](https://github.com/The-Login/DNS-Analysis-Server/blob/main/DNS-Analysis-Server/dns_proxy.py)). The DNS proxy proxies DNS requests to and from the ADNS and can therefore perform the described actions.  
The server's purpose is therefore, as described, to act as an authoritative DNS analysis server. 

### How do I know if a DNS setup is vulnerable?
The various analysis methods of the analysis server check for requirements of **DNS attacks**.  
If all requirements for a DNS attack are fulfilled, the attack should be practically possible.  
Currently, the DNS Reset Checker can be used to test for 2 DNS attacks:
- Kaminsky attacks
- IP fragmentation attacks

What exactly are their attack requirements, one might ask. Here's a summary of some **main** requirements:  
- Kaminsky attacks:
    1. Low/No random distribution of source ports
    2. No usage/enforcement of DNS security features (DNS SEC, DNS cookies, 0x20 encoding, etc.)
- IP fragmentation attacks:
    1. The DNS resolver of the web application accepts IP fragmented DNS responses
    2. No usage/enforcement of DNS security features (DNS SEC, etc.)
    3. Maximum EDNS buffer size larger than 1232 

For example, if the DNS infrastructure is vulnerable to Kaminsky attacks, you might see the following scatter plot via the log analyzer:  
![log_analyzer_static_source_ports](https://user-images.githubusercontent.com/84237895/188707061-18cb18f9-0f37-4ffe-bbf3-18ba29358d64.PNG)  
In this case, only port 53 was used as source port by the DNS resolver.  
The other requirements mentioned can be checked by reading the "General Info" section of the log analyzer output or by analyzing the dns_log.txt log entries directly.
![log_analyzer_overview](https://user-images.githubusercontent.com/84237895/188706313-ab9bd732-676c-408f-8344-043a0c5827df.PNG)  
*As already mentioned, for a more in-depth look at this topic check out [this](https://sec-consult.com/blog/detail/forgot-password-taking-over-user-accounts-kaminsky-style/) and [this](https://sec-consult.com/blog/detail/melting-the-dns-iceberg-taking-over-your-infrastructure-kaminsky-style/) blog post.*  
### Extra Tooling
In the [tools/](https://github.com/The-Login/DNS-Analysis-Server/tree/main/tools) directory you can find some neat utility scripts.
- **domain_mapper.py**: This script can be used to create a mapping between analysis IDs (e.g., 0100001337) and domain names (e.g., google.com). It's great when analyzing thousands of domains, since you don't have to map analysis IDs to domain names manually! So, **BEFORE** starting your analysis server, execute:  
```sudo python3 domain_mapper.py --domain-file domains.txt --version-number 15```  
- **emailer.py**: This script can be used to send e-mails to trigger DNS resolutions. Execute this script **AFTER** starting the analysis server:  
```python3 emailer.py --testing-domain analysis.example --domain-file domains.txt --version-number 15 --start-method 0 --start-id 0```  

