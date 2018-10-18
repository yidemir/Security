<?php
use Demir\Security\CsrfGuard;
require __DIR__ . '/../vendor/autoload.php';
session_start();
?><!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title></title>
</head>
<body>
  <form method="post" action="TestCsrf.php">
    <?= CsrfGuard::getField() ?>
    
    <input type="submit" value="Gönder">
  </form>
</body>
</html>