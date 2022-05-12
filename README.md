# Tricks-Web Penetration Tester
- [x] In Construction

## WAF

### Manual Detection:

-> Cookies

-> Server Cloaking

-> Response Codes

-> Drop Action

-> Pre-Built-In Rul3es

### Response code WAF'S

-> mod_security -> 406 Not Acceptable

-> AQTRONIX WebKnight -> 999 No hacking

## Host Obfuscation

#### Types:
-> DWORD
  
-> OCTAL 
  
-> HEX
  
-> HYBRID
Tool:

https://www.silisoftware.com/tools/ipconverter.php

## TOOL's:

wafw00f 

https://github.com/EnableSecurity/wafw00f

nmap --script=http-waf-fingerprint

https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html

imperva-detect

https://raw.githubusercontent.com/vmfae-iscteiulpt/imperva-detect/master/imperva-detect.sh

### Others:

https://github.com/0xInfection/Awesome-WAF

## Cross-Site Scripting (Reflected, Stored, DOM, Mutation)

## Protection XSS

-> XSS Auditor and XSS Filter

https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

https://www.chromium.org/developers/design-documents/xss-auditor/

https://portswigger.net/daily-swig/xss-protection-disappears-from-microsoft-edge

https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/X-XSS-Protection

-> Wordlists for XSS Bypass

https://gist.githubusercontent.com/rvrsh3ll/09a8b933291f9f98e8ec/raw/535cd1a9cefb221dd9de6965e87ca8a9eb5dc320/xxsfilterbypass.lst

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt

https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt

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

Examples:

xss.txt

XSS Keylogger

https://rapid7.com/blog/post/2012/02/21/metasploit-javascript-keylogger/

https://github.com/hadynz/xss-keylogger

XSS Mutation

http://www.businessinfo.co.uk/labs/mxss/

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

x69 hex i

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

### PHP Obfuscation

#### PHP Non-Alphanumeric 

$\_="{"; #XOR char

echo $\_=($\_^"<").($\_^">").($\_^"/"); #XOR = GET

//GET

https://web.archive.org/web/20160516145602/http://www.thespanner.co.uk/2011/09/22/non-alphanumeric-code-in-php/

#### Tools

-> phponalpha

-> phponalpha2

https://hackvertor.co.uk/public

### PHP Obfuscation - base64+gzdeflate

obufscation.php

## Local File Inclusion - LFI

### LFI - files for fuzzing

Wordlist LFI - Linux:

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

Wordlist LFI - Windows:

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

### Payloads for bypass

bypass_lfi.txt

### Others:

Wordlist for SQL Injection - Bypass

https://gist.githubusercontent.com/zetc0de/f4146eb278805946ab064a753eac6a02/raw/e126452093b9cde7f82eff14a15f8ceca8188701/sqli-bypass-waf.txt

Doc for SQL Injection - Bypass

https://github.com/OWASP/www-community/blob/master/pages/attacks/SQL_Injection_Bypassing_WAF.md

Wordlists for SQLI e XPath - Authentication Bypass:

https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/Auth_Bypass.txt
