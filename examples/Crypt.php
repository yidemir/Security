<?php

use Demir\Security\Crypt;

require __DIR__ . '/../vendor/autoload.php';

$crypt = new Crypt('Q5oQpbppt2nC+XC5/Eg1qdnosi+gZ7XveuLtV5fcZ1w=');
$secret = $crypt->encrypt('foobar');
$foobar = $crypt->decrypt($secret);