<?php
if(empty($_GET['payload'])) die("payload ?");
$payload = ($_GET['payload']);

$headers = array(
        "Expect: 100-continue",
        "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
    );

/***********
 * REQUEST 1
 ************/
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'http://site.com/register');
curl_setopt($ch, CURLOPT_POST, 1);

//Insert registration and payload fields here
curl_setopt($ch,CURLOPT_POSTFIELDS,"payload in paramters");
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);

$result1 = curl_exec($ch);
echo $result1;
curl_close($ch);

/***********
 * REQUEST 2
 ************/
$ch2 = curl_init();
curl_setopt($ch2, CURLOPT_URL, 'http://site.com/login');
curl_setopt($ch2, CURLOPT_POST, 1);

//Insert login fields here
curl_setopt($ch2, CURLOPT_POSTFIELDS, "email=$payload&password=pass");

curl_setopt($ch2, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch2, CURLOPT_COOKIEJAR, 'cookie.txt');
curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);
$result2 = curl_exec($ch2);
echo "\n$result2";

/***********
 * REQUEST 3
 ************/
curl_setopt($ch2, CURLOPT_URL, 'http://site.com/view');
$html = curl_exec($ch2);
curl_close($ch2);
$ok1 = str_replace("\n"," ", $html);
$ok2 = str_replace("   "," ", $ok1);

//Insert a regex to filter the response below
preg_match_all('regex',$ok2,$prepare_regex);
$regex_final = implode(",", $prepare_regex[1]);
echo $regex_final;
?>
