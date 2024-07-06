# Regex Generation

## Regex

A regular expression (**regex**) is sequence of character that imply a pattern to match on a string. It was developped on language theory and is widely used on cyber security and threat detection; It's typically used in stuff such as input validation, find strings that match patterns, errors detection and so on..

Regular expressions are well known for their matching speed and the great accuracy too, which something really needed to robust the server's security.

Our IDS/IPS program depends a lot on **regex** and in many cases too; such as ddos mitigation and sanitization; but we, today, will focus on the usage and implementation of regex on scrapping bots prevention and detection. We will also learn how to make new dynamic **regular expression**, We will speak about this in another part.


### Regex syntax

In this section, we will explain regex syntax to help you become more familiar with the concepts discussed in the subsequent parts of the article.

- **Character** : Matches the exact character sequence in the string. Example: cat matches "cat" in "concatenate". Example : ``regex 10 matches "10"; regex helloworld matches "helloworld"``
- **Or Operatior** **|** (Alternation): Acts like a boolean OR, allowing you to match one pattern or another. Example: a|b matches "a" or "b".
- **Quantifiers**
    - **\***: Matches 0 or more occurrences of the preceding element.
Example: ``ca*t matches "ct", "cat", "caaaat"``.
    - **+**: Matches 1 or more occurrences of the preceding element.
Example: ``ca+t matches "cat", "caaaat" but not "ct"``.
    - **?**: Matches 0 or 1 occurrence of the preceding element.
Example: ``ca?t matches "ct" and "cat"``.
    - **{n}**: Matches exactly n occurrences of the preceding element.
Example: ``a{3} matches "aaa"``.
    - **{n,}**: Matches n or more occurrences of the preceding element.
Example: ``a{2,} matches "aa", "aaa", etc``.
    - **{n,m}**: Matches between n and m occurrences of the preceding element.
Example: ``a{2,4} matches "aa", "aaa", or "aaaa"``.

- **Meta-characters**
    - **.** (Dot): Matches any single character except newline.
Example: ``c.t matches "cat", "cot", "cut"``.
    - **\\**: Escape character used to treat metacharacters as literal characters.
Example: \\. matches a dot.

- **Position Anchors**
    - **^**: Matches the beginning of a string or line.
Example: ``^cat matches "cat" at the start of a string``.
    - **\$**: Matches the end of a string or line.
Example: ``cat$ matches "cat" at the end of a string``.
    - **\b**: Matches a word boundary.
Example: ``\bcat\b matches "cat" as a whole word``.
    - **\B**: Matches a non-word boundary.

- **Predefined Character Classes**

    - \d: Matches any digit, equivalent to [0-9].
    - \D: Matches any non-digit.
    - \w: Matches any word character (alphanumeric + underscore), equivalent to [a-zA-Z0-9_].
    - \W: Matches any non-word character.
    - \s: Matches any whitespace character.
    - \S: Matches any non-whitespace character.



| **Use Case**                | **Regex Pattern**                                     |
|-----------------------------|-------------------------------------------------------|
| **Email Pattern Match**     | `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`    |
| **Phone Number Validation** | `^(\+\d{1,3}[- ]?)?\d{10}$`                           |
| **URL Validation**          | `^https?:\/\/[^\s/$.?#].[^\s]*$`                      |
| **Find and Replace in Text**| `s/\bcat\b/dog/g`                                     |
| **Sanitize Input**          | `s/[^\w\s]//g`                                        |
| **Data Cleaning**           | ``s/^\s+\|\s+$//g``  

**table 1** : example of some regex use cases

### Regex and cyber security

Regular expressions (REGEXs) have really showed how important and effective they are in cybersecurity. Many antiviruses already implement a lot of different techniques to detect and mitigate threats.

One of many examples, is using regex on sanitizating web application attacks such as [SQLIA](https://github.com/hcn1z1/HCDS-Topics/blob/main/hcn1z1/reverse_proxy/SQLIA.md) which we have already discussed on [reverse proxy](https://github.com/hcn1z1/HCDS-Topics/blob/main/hcn1z1/reverse_proxy). It can be used on extracting patterns and detecting new attacks which will allow for better behavior-analyse too.

Another example with malware detection, where regex can be used to match malware signature like known **byte sequences** for example ``\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00``. It can be used, for example, to analyse `dll` that are typically included by malware and packets sent by [botnets](https://www.cloudflare.com/learning/ddos/what-is-a-ddos-botnet/).

## Regex generation

Regex generation can be a really important aspect on cybersecurity. Making a good regex generator will really solves a lot of problems and open a lot of doors for more advanced research and that's why We were doing our best thinking about new ways and methods to implement **regex** and **regex generation** on our IDS/IPS system.

Let's first speak about some common concepts of regex generation.

### YARA

**Yet Another Recursive Acronym** (YARA) is a framework that help cyber security experts and malware researcher to identify and classify malware samples by recognizing patterns. Think of it as a set of rules, each rule is a pattern that identifies malware signature. It can tells which files matches the description of known malwares.

YARA automates the detection process, making it faster and more efficient to detect and protect against threats.

**Example of YARA rule**:
```
rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
    condition:
        $a or $b or $c
}
```

- **Rules** : YARA rules are like checklists. They describe what you’re looking for in a file. Each rule consists of conditions that must be met for YARA to identify the file as suspicious or malicious.

- **Strings** : These are specific sequences of text or bytes that the rule is trying to find.

- **Conditions** : Conditions are the logic part of the rule. They define how the strings must appear for the rule to be triggered.


### Clustering 

**Clusters** are groups of similar items or data points that are grouped together based on certain characteristics or patterns. The concepts of clustering is widely used in various fields of computer science, including data analysis, machine learning and of course cybersecurity. 

**Cluster analysis**, or **clustering**, involves grouping a set of objects so that those within the same group (known as a cluster) are more similar to each other than to objects in other groups (clusters). This similarity is defined based on specific criteria set by the analyst. Clustering is a key task in exploratory data analysis and a widely used technique in statistical data analysis.<sup>[1](https://en.wikipedia.org/wiki/Cluster_analysis)</sup>

**Clustering** is an unsupervised learning technique that doesn't require labeled data, focusing only in finding similarities and identify patterns.<sup>[2](https://www.explorium.ai/blog/machine-learning/clustering-when-you-should-use-it-and-avoid-it/)</sup>


**How clustering works**

- **Data Collection** : Gather data points that you want to analyze. In cybersecurity, this could be logs, network traffic data, or executable files.
- **Feature Extraction** : Identify and extract relevant features from the data. For malware detection, this might include specific byte sequences, system calls, or behavioral patterns.
- **Clustering Algorithm** : Apply a clustering algorithm to group similar data points. Common algorithms include K-means, hierarchical clustering, and **DBSCAN** (Density-Based Spatial Clustering of Applications with Noise).
- **Cluster Analysis** : Analyze the resulting clusters to identify patterns or insights. In cybersecurity, this might involve examining clusters of malware to identify new variants or attack strategies.

**Benefits of Clustering**

- **Efficiency**: Quickly groupe large datasets for analysis
- **Insightful**: Find hidden patterns or relationship within data
- **Predictive**: Helps in predicting behavior

### GenRex 

Genrex is an open-source regex generation tool for the sole purpose of identifying similarities and patterns in artifacts (**extracted data**). It takes a set of 
positive artifacts and create regular expressions from it.

Here is a following example of a script using genrex tool :

```python
import re
from scapy.all import rdpcap, UDP , TCP
import numpy as np
import genrex

file = "data.pcap"
packets = rdpcap(file)


generationtype = genrex.InputType.MUTEX

source = {}
moduler = 50
i = 0

all_data = []
for packet in packets:
    # Check if the packet has an IP layer
    if packet.haslayer('IP') and packet.haslayer(UDP):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        raw_payload = packet['Raw'].load.hex() if packet.haslayer('Raw') else None

        print(f"Source IP: {ip_src}",end="\r")
        if raw_payload:
            step = int(len(raw_payload)//moduler)
            all_data.append([raw_payload[i*moduler:(i+1)*moduler] for i in range(step)])
    if i == 100000:
        break
    i +=1

print("Initial length :",len(all_data))

# remove 0
while [] in all_data:
    all_data.remove([])

for data in all_data:
    if len(data)<=2:
        all_data.remove(data)

print("New Length :",len(all_data))

all_compilation = all_data[:int(len(all_data)*0.8)]
for j in range(len(all_compilation)):
    if source.get(f"source{len(all_compilation[j])}") == None:
        source[f"source{len(all_compilation[j])}"] = []
    source[f"source{len(all_compilation[j])}"] += all_compilation[j]

# compile prediction
results = genrex.generate(
     cuckoo_format=False,
     store_original_strings=False,
     input_type=generationtype,
     source=source
 )


print("Generation done: \n\n")
patterns = [res.return_printable_dict()["regex"] for res in results]
print("detected patterns : {} pattern".format(len(patterns)))
```

I made this script in order to identify patterns on **DDoS** attacks; But this tool wasn't made for that same purpose. Large sequence of data with doesn't let us really generate good regex tho i could make some regex with that code that has 3% success rate with 172 different patterns on tested [pcap file](https://www.solarwinds.com/resources/it-glossary/pcap).

## Implementaion 

**TODO**: we will discuss the implementation of [GenRex](https://github.com/avast/genrex) and Clusters in detecting automated bots on our IDS/IPS system. 

