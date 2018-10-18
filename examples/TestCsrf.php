<?php

use Demir\Security\CsrfGuard;

require __DIR__ . '/../vendor/autoload.php';

session_start();
var_dump(CsrfGuard::checkToken());