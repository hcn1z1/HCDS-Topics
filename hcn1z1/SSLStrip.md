# SSL Strip Attack

## What's SSL?

**SSL** (Secure Socket Layer) is a protocol that helps in establishing an encrypted connection between two seperate computers (typically client-server connections).

Its successor **TLS** (Transport Layer Security) which often refer to as **SSL/TLS** it's a more reliable encryption protocol. the last version was **TLS 1.3**. [1](https://www.ssl.com/faqs/faq-what-is-ssl/)

## What's SSL certificate?

SSL certificate is a kind of digital document that helps the browser to exchange three keys with the server. **private key**, **public key** and a **session key**, the document is refered too typically as **CA (Certificate Authority)**


<figure align="center">
  <img src="https://ee2cc1f8.rocketcdn.me/wp-content/uploads/2019/07/ca-diagram-b.png" alt="CA Certificate">
  <center>Figure 1: CA Certificate Overview</center>
</figure>

<br>
<br>

All the data encrypted by **private key** will be decrypted by **public key**. and vice verse, all the data encrypted by **public key** will be decrypted by **private key**.[1](https://www.ssl.com/faqs/faq-what-is-ssl/) This is an advanced mode of encryptions called *asymmetric cryptography*[2](https://www.techtarget.com/searchsecurity/definition/asymmetric-cryptography)


## SSL Usage

the typical usage of SSL (Secure Socket Layer) is on web browsering security via the [**HTTPS**](https://www.ssl.com/faqs/what-is-https/) protocol. All public HTTPS websites are configured with an **SSL/TLS** configuration which include an SSL/TLS certificate that is signed by a trusted **CA**.

**SSL/TLS** and **HTTPS** allows users to transmit confidential informations securely because of the various layers of security they offer from **encryptions** to **authenticity** and **integrity** (*certificate can't get altered by a* **MITM**).



## MITM attack (Man in The Middle)

an **MiTM attack**, in definition, is a *cybersecurity threat* where the attacker intercept the data on a client-server connection or acting as both-ends as mutating their roles. The attacker can insert himself to send or receive information that wasn't meant to be sent to him.

<figure align="center">
  <img src="pictures/ssl strip/mitm.png" alt="CA Certificate">
  <center>Figure 2: MiTM Attack</center>
</figure>


<br>
<br>

### WIFI Eavesdropping

One of the common MiTM attacks is the WIFI Eavesdroppig, where the attacker creates a fake wifi endpoint that has the ASN (wifi name) of the target while DDoSing the actual endpoint (which will lead to a connection denial). the attacker then will insert a malicious code to steal important data such as WIFI password and so on.

**Common tools** :
- [Wireshark](https://www.wireshark.org/)
- [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)

### ARP Spoofing

Address Resolution Protocol (ARP) spoofing is a technique used in MiTM attacks within a local network (LAN) where the attacker sends fake ARP messages onto the network including their MAC address another **IP** address (such as gateway IP) which will lead for all other devices to send the data to his device. this is a very common MITM attack it target mostly the no secure connections (such as HTTP) but can envolve to wider and more dangerous attacks.

**Common tools** : 
- [Arpspoof](https://github.com/smikims/arpspoof)
- [Ettercap](https://www.ettercap-project.org/)

## Types of MiTM

I would like to devide **MiTM** attacks into three different types, **intercepters**, **interconnecters** and **spoofer**.

- **Intercepters** are the MiTM attacks where the attacker doesn't try to force a connection between him and the target but only act as a proxy between the target and the router.

- **Interconnecters** are the MiTM attacks where the attacker force a connection between him and the target and act as a proxy between the target and the server (act as the server itself). This happens sometimes in cracked apps where the attacker force the APP to connect to his server instead of the server itself and *imutates* the server.

- **Spoofers** are the MiTM attacks where the attacker spoof a connection to exploit the target informations without an inital interaction with the server or router.

## SSLStrip Attack

**SSL stripping** is a technique where an attacker intercepts the communication between a user's browser and a website, typically during the initial handshake where the browser attempts to establish a secure HTTPS connection. The attacker forces the connection to revert to HTTP, which is not secure.

**SSL stripping** allows the attacker to access the **insecure** data transmitted by the target which is a huge threat. The hacker will be able easily to steal confidential information such as password, credit cards ext..

**Common tools** : 
- [SSLStrip](https://github.com/moxie0/sslstrip)
- [MITMproxy](https://github.com/mitmproxy/mitmproxy)
- [Burp Suite](https://portswigger.net/burp)


<figure align="center">
  <img src="pictures/ssl strip/SSLStrip.png" alt="SSL Strip">
  <center>Figure 3: Topology of an <a href = "https://www.computerweekly.com/tip/Sslstrip-tutorial-for-penetration-testers">SSL Attack</a></center>
</figure>

<br>
<br>

To explain **SSL Strip attack** in a better way, consider the next example.

The attacker and target are connected to the same local network ([LAN](https://www.cisco.com/c/en/us/products/switches/what-is-a-lan-local-area-network.html)), the attacker act as a **proxy** between the server and the target;

The target call the website but the attacker respond and *the conversation goes like following* :

*Attacker to target* :
```

A : Hi, I am the website you are requesting, unfortunately we can't use HTTPS protocol right now  :'( but we support HTTP fortunately :D ,can you instead send the raw insecure data?

T : Oh, I didn't know. here you go : MY PASSWORD IS NOTSECUREPASSWORD
```

*Attacker to website* : 
```
A : Hi, I am a legit user UwU. but I can't start a legit secure connection :'( is that okay?

W : Oh the poor thing ToT of course. It is totally permitted. lemme help you out !

A : Hehe, MY PASSWORD IS NOTSECUREPASSWORD
```

## Mitigating SSLStrip Attack

We introduce in this part two different setups to mitigate SSLStrip, first (and the one to implement in our project) is the **Server side SSLA metigation**. the other one is the **Client-side detecting SSLA** presented on [HProxy](https://link.springer.com/chapter/10.1007/978-3-642-14215-4_12).

## Server-side

If you take your time analysing the previous example to identify the **technic** , or better say the **exploit** that the attacker used to attack the SSL protocol, is the fact that the server accept an insecure connection. which will allow the attacker to act as a proxy between the server and client. Or in some cases, using an invalid **CA** to connect with the server.



### HSTS (HTTP Strict Transport Security)
A common way to prevent this kind of attacks is using the HTTP Strict Transport Security (HSTS) policy.

**HSTS**  is a mechanism that helps protect websites against protocol downgrade (in other words SSL stripping) attacks and [cookies hijacks](https://www.invicti.com/learn/cookie-hijacking/). It allows web servers to declare that clients (*such as web  browsers*) should only interact with it using HTTPS only.

**<span style="font-size:1.1em;">Implementation</span>**

include ``Strict-Transport-Security`` header in the HTTPS responses. This tells the browsers to only connect via HTTPS for specified amount of time. even if the user clicks or access an **HTTP** (*not secure*) link.

**Example** : ``Strict-Transport-Security: max-age=31536000; includeSubDomains; preload``

**<span style="font-size:1.1em;">Flask implementation</span>**

this is a small code for implementing **HSTS** policy with python specificly **Flask** framework
```python
from flask import Flask, redirect, request, make_response

app = Flask(__name__)
hsts_headers = 'max-age=31536000 includeSubDomains; preload'

@app.before_request
def enforce_https():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)

@app.after_request
def set_hsts_header(response):
    response.headers['Strict-Transport-Security'] = hsts_headers
    return response
```

### CSP (Content Security Policy)

A **content security policy** is a security standard that was made to add an additional layer of web security against attacks (**eg.:** XSS, clickjacking). This policy allows developer to restrict which resources can be loaded in certain pages. for example; if the developer doesn't want you to access *login.js* from */signup*, he has to use **CSP**.[3](https://www.imperva.com/learn/application-security/content-security-policy-csp-header/)


While **CSP** doesn't mitigate SSL Stripping directly, but it can enhance the security system to prevent loading mixed content and restric data to secure origins

**<span style="font-size:1.1em;">Implementation</span>**

You can implement **CSP** in your response headers. An example of a valid **CSP** header : 

``Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.example.com; img-src 'self' https://images.example.com; style-src 'self' 'unsafe-inline';
``

**<span style="font-size:1.1em;">Flask implementation</span>**

the same way we implemented HTST on python, we can implement **CSP** too in our response header
```python
from flask import Flask, render_template, make_response

app = Flask(__name__)

@app.route('/')
def home():
    response = make_response(render_template('index.html'))
    # Policies or Rules specified to path /
    csp_policy = {
        "default-src": "'self'",
        "script-src": "'self' https://trustedscripts.example.com",
        "img-src": "'self' https://trustedimages.example.com",
        "style-src": "'self' 'unsafe-inline'",
        "frame-src": "'none'"
    }
    csp_header_value = '; '.join([f"{key} {value}" for key, value in csp_policy.items()])
    response.headers['Content-Security-Policy'] = csp_header_value
    return response

if __name__ == '__main__':
    app.run(debug=True)
```

## Client-side

A solution for detecting and mitigating SSL Strip on client levels is HProxy (**History Proxy**), a program that use browser history. They use client browser history to train with requests and responses of the websites that the client use regulary and build a profile for each.

This solution is not quite very efficient as it uses personal data but it can be powerful in times an attacker access your network.

Another solution can be spreading awareness to client.

I know that those solutions doesn't seem efficient but honestly, it depends totally on the user himself and the power of the OS firewall at some point.

## Conclusion

**SSL Stripping** represents a very dangerous, *client-side*, threat and as a promising upcoming mitigation system, we are committed to implementing effective mitigation strategies. While the solution may not appear to be so efficient, but such that SSL/TLS protocol exists that such attacks can still happen. We have introduced best mitigation techniques along with their technical implementation too.