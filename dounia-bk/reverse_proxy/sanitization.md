# Sanitization

## Data Sanitization
**Data sanitization** is a critical process in data management and security, ensuring that sensitive information is permanently deleted to prevent unauthorized access or use and to ensure it cannot be recovered. 
Ordinarily, when data is deleted from storage media, the media is not really erased and can be recovered by an attacker who gains access to the device. This raises serious concerns for security and data privacy. With sanitization techniques, sensitive data is cleansed so there is no leftover data on the device. These techniques vary based on the type of data, the context of its use, and the required level of security including data masking, encryption, pseudonymization, anonymization, and data redaction.

### Data Masking
**Data masking** is a way to create a fake, but a realistic version of your organizational data. The goal is to protect sensitive data, while providing a functional alternative when real data is not needed—for example, in user training, sales demos, or software testing.

**Data masking** processes change the values of the data while using the same format. The goal is to create a version that cannot be deciphered or reverse engineered. There are several ways to alter the data, including character shuffling, word or character substitution, and encryption.

### Anonymization  
**Data anonymization** is the process of protecting private or sensitive information by erasing or encrypting identifiers that connect an individual to stored data. For example, you can run Personally Identifiable Information (PII) such as names, social security numbers, and addresses through a data anonymization process that retains the data but keeps the source anonymous.

However, even when you clear data of identifiers, attackers can use de-anonymization methods to retrace the data anonymization process. Since data usually passes through multiple sources—some available to the public—de-anonymization techniques can cross-reference the sources and reveal personal information.

The [General Data Protection Regulation](https://gdpr.eu/what-is-gdpr/) (GDPR) outlines a specific set of rules that protect user data and create transparency. While the GDPR is strict, it permits companies to collect anonymized data without consent, use it for any purpose, and store it for an indefinite time—as long as companies remove all identifiers from the data.



## HTML Sanitization

**HTML Sanitization** by definition, is the production of a "safe" HTML code from only including allowed ``tags`` and ``attributes`` while emitting all possible *attacks*. **HTML Sanitization** can be used to protect against web attacks such as [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting), [SQLIA](https://en.wikipedia.org/wiki/SQL_injection) ect..


Sanitization is basically processed through a *whitelist*/*blocklist* approach. It simply includes only the safe features (such as safe ``tags`` or ``attributes``) in order to generate a **safe** HTML document/code.

Sanitization also detects other form of vulnerabilities on **application layer** and remove them. 

### Why sanitize html document on reverse proxy ?

Sanitizing Html on reverse proxy will give the coder the ability to analyse new patterns and fully customize his **detection**/**prevention** techniques. this will allow also the server to focus on the webapp features instead of maintaining the security.

Reverse proxy can also work as a bridge between the server and IPS/IDS system implemented (such as HCDS) which will allow for enhancing the security and prevention of multi-attacks

Reverse proxy can also omit **insecure** connections, that may perform [ssl strip attacks](), elimating danger and securing the server.

