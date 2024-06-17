# Unrestricted File Upload 

## Introduction

In a world where communication became rather an essential in our lifes, people frequently upload their valuable assets (such as pictures and videos) all the time which obviously had created a real-time threat for the web applications enabling different type of uploads functionalities. **Unrestricted file upload** presents a risk to these applications. 

Hackers always attend first to upload a malicious code to a system in order to control it and here comes **UFU** vuln which give them this option on a golden plate.

But what is exactly **UFU**?

### Definition

Unrestricted file upload, as what the name tells, is a web vulnerability where the web server doesn't sanitize correctly the uploaded files and technically doesn't restrict certain type of files (such as scripted files) from getting uploaded.

Unrestricted file upload can be also considered as a **DOS** attack where the attack overwhelm the webserver with millions of new file that will technically slow his server if not crush it in the first place.<sup>[1](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)</sup>


We can disguinch two different problem:

**<span style="font-size:1.1em;">First problem</span>**

The first one locate on the metadata such as the **path** and **file name**. Those errors most of the time are provided by the HTTP server where the coder doesn't take in consideration the **UFU** vulnerability.


In order to explain this, we consider examining the following example.

Consider the endpoint ``/api/v1/upload``, which accepts three parameters: ``type``, ``content`` and ``file name``. **type** parameter can either be *image* or *video*. This distinction is used solely to differentiate the storage paths for images from those for videos.

We upload a malicious content with the following code

```curl
curl -X POST http://example/api/v1/upload \
     -F "type=image" \
     -F "content=@/path/to/your/image.php" \
     -F "file name=uploaded_image.php
```

As expected, the server processes the upload and returns a path to the uploaded file:

```json
{
    "status": 201,
    "path": "http://example/content/images/uploaded_image.php"
}
```

By accessing this path, an attacker could potentially execute the malicious script, gaining control over the server's content.


**<span style="font-size:1.1em;">Second problem</span>**

Another issue the system may accounter, is the size of the file, this can initial a **DOS** attack with uploading unlimited amount of files or unlimited size file. Let's say for example that the server doesn't limit how much files you upload but limit the size of content. You can make a small script to upload infinite number of files

Example script that generate random files with no content.

```python
import string
import random
import requests

url = "http://example/content/images/uploaded_image.php"
content = b""
type_ = "image"

while True:
    try : 
        response =  requests.post(url,timeout = 10,json = {
            "type":type_,
            "content":content,
            "file name":"".join([random.choices(list(string.ascii_letters),k=10)]) + ".png"
        })
    except :
        print("Successful [Server probably crashed]")
```

## Risk Factors
This list is uploaded from <sup>[2](https://github.com/OWASP/www-community/blob/master/pages/vulnerabilities/Unrestricted_File_Upload.md)</sup>

  - The impact of this vulnerability is high, supposed code can be
    executed in the server context or on the client side. The likelihood
    of detection for the attacker is high. The prevalence is common. As
    a result the severity of this type of vulnerability is high.
  - It is important to check a file upload module's access controls to
    examine the risks properly.
  - Server-side attacks: The web server can be compromised by uploading
    and executing a web-shell which can run commands, browse system
    files, browse local resources, attack other servers, or exploit the
    local vulnerabilities, and so forth.
  - Client-side attacks: Uploading malicious files can make the website
    vulnerable to client-side attacks such as
    [XSS](Cross-site_Scripting_\(XSS\) "wikilink") or Cross-site Content
    Hijacking.
  - Uploaded files can be abused to exploit other vulnerable sections of
    an application when a file on the same or a trusted server is needed
    (can again lead to client-side or server-side attacks)
  - Uploaded files might trigger vulnerabilities in broken
    libraries/applications on the client side (e.g. iPhone MobileSafari
    LibTIFF Buffer Overflow).
  - Uploaded files might trigger vulnerabilities in broken
    libraries/applications on the server side (e.g. ImageMagick flaw
    that called ImageTragick\!).
  - Uploaded files might trigger vulnerabilities in broken real-time
    monitoring tools (e.g. Symantec antivirus exploit by unpacking a RAR
    file)
  - A malicious file such as a Unix shell script, a windows virus, an
    Excel file with a dangerous formula, or a reverse shell can be
    uploaded on the server in order to execute code by an administrator
    or webmaster later -- on the victim's machine.
  - An attacker might be able to put a phishing page into the website or
    deface the website.
  - The file storage server might be abused to host troublesome files
    including malwares, illegal software, or adult contents. Uploaded
    files might also contain malwares' command and control data,
    violence and harassment messages, or steganographic data that can be
    used by criminal organisations.
  - Uploaded sensitive files might be accessible by unauthorised people.
  - File uploaders may disclose internal information such as server
    internal paths in their error messages.

## Mitigation and sanitization

### I . FUSE 

FUSE is an open source framework designed to detect and sanitize vulnerabilities associated with **Unrestricted File Upload** (UFU). It can identify **10** different type of UFU and **Unrestricted Execuable File Upload** (UEFU). This framework aims to identify UFU/UEFU vuln that enable code execution from uploaded seed files that are processed by PHP interpreters (such as XHTML PHP files) on Apache servers or executed by the major three web browsers —Chrome, Firefox, and Microsoft Edge.<sup>[3](https://www.researchgate.net/profile/Seongil-Wi-2/publication/339495940_FUSE_Finding_File_Upload_Bugs_via_Penetration_Testing/links/5e9d9a7f299bf13079aa9dbe/FUSE-Finding-File-Upload-Bugs-via-Penetration-Testing.pdf)</sup>

You can find the whole source code here [FUSE](https://github.com/WSP-LAB/FUSE)

![FUSE](./pictures/file%20upload%20vulnerability/fuse.png)
<p align="center">Figure 1: Overview of FUSE architecture.<sup>3</sup></p>



### II . Metadata and regex

Another approach could be to utilize regular expressions (**regex**) to detect and then sanitize any potential attacks. Additionally, configuring the upload function to modify the file name, limiting both the number and size of uploaded files, could further enhance security. Finally, instead of returning a direct path to the uploaded file, the system could direct users to an **HTML page** that displays the image. This minimizes the critical use of **PHP** in handling file uploads.

[OWASP](https://owasp.org/) suggested the following sanitization code 


**Insecure config**
```xml
<FilesMatch ".+\.ph(p([3457s]|\-s)?|t|tml)">
    SetHandler application/x-httpd-php
</FileMatch>
```
**Secure config**

```xml
<FilesMatch ".+\.ph(p([3457s]|\-s)?|t|tml)$">
    SetHandler application/x-httpd-php
</FileMatch>
```

another regex is just to see the ``file name`` extension.

``RE = \.(exe|dll|bat|sh|php|js|html|htm|jsp|asp|aspx|cgi|pl|py|rb|vbs|msi|ps1|cmd)$``

 It's not very effective since it can be **spoofed** technically and it's still enable the hacker to upload a malicious script to the server. This's why we are going use another technique to analyse all the files we upload using [mimetype](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types).


### MIMEType detection

A MIME type (Multipurpose Internet Mail Extensions type) is a standard way of classifying file types on the internet. Originally developed for email, MIME types have become integral in other applications as well, such as web browsers and servers, to determine how to handle different file formats.<sup>[4](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types)</sup>


**MIME** types consist of two parts:
- Type: The primary category, such as text, image, video, application, etc.
- Subtype: More specific identification of the file format, such as plain (for text/plain), jpeg (for image/jpeg), html (for text/html), or mp4 (for video/mp4).

Fortunately, we can dynamically detect the MIME type with python; The following code tells the real MIME type of the file even if it gets spoofed : 


```python
import magic
import io

def get_real_mime_type(file_content : bytes):
    container = io.BytesIO(bytes)
    container.seek(0) 
    mime = magic.Magic(mime=True)
    mime_type:str = mime.from_buffer(container)
    if mime_type.startswith('image/'):
        return True
    elif mime_type.startswith('video/'):
        return True
    else:
        print("The file is neither an image nor a video.")
        return False
```

## Implementation


In our implementation, the mitigation will happen in reverse proxy and HCDS Javascript SDK.

- The **reverse proxy** will intercept all the income requests and detect the attack with regex firstly then with MIME type if it's enabled on config file ``detect_mimetype = true``. the reverse proxy will discard the file and send an error to the server which the client server should receive and interpreter.

- The **SDK** will check all the different metadata, size, content-type, and so on. with the interaction with **HCDS Server** ,which saves every new update, it will stop the user from uploading more files.

- **Reverse proxy** has two modes, ``default`` mode and ``attack mode``. on ``default`` mode the reverse proxy check regularly the files and send the requests as mentioned to the server. however, in ``attack mode``, the server will only check content and choose by length, pattern and other features if the packet should be discarded or went through. The process consist of saving the most recent **detected attack packets** and analyse them all together and stop any threat for that time. It will eventually **rate limit** or redirect users to **recaptcha**. This way, we decrease the attack **DOS** effictiveness but still keep the legit users around.


## Conclusion

In this topic we discussed the impact of U(E)FU vulnerability and as we explored that these type of vulnerabilities give **attackers** a gateway to inject malicious code but also exposes the server to a potential **DOS attack** that can slow the server operations and corrupt its resources as well. Recognizing the nature of these threats is crucial for developing a defense system such as **HCDS**.

To combat these risks, adopting frameworks like [FUSE](https://github.com/WSP-LAB/FUSE), which can effectively identify and mitigate various types of upload vulnerabilities, is essential. Moreover, supplementing these tools with strong validation mechanisms such as regex-based detection and MIME type verification can fortify security measures. by implementing such strategy on content level and metadata level as well we can significally reduce the attack effictiveness and potentials.

Finally, the cyber security is continuously evoling and so are the attackers getting better and better to find some twist methods to bypass all the mitigation methods. This essentially require maintenance and daily monitoring. We attend to adopt with these evolutions to ensure that our system not only defend against current threats but also prepared for future challenges.