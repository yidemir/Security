<?php

use Demir\Security\SimpleCaptcha;

require __DIR__ . '/../vendor/autoload.php';

session_start();

$c = new SimpleCaptcha('10', '1234567890');
$c->showImage();