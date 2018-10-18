<?php

use Demir\Security\JWT;

require __DIR__ . '/../vendor/autoload.php';

$key = 'mrQqaXNebcY6Bfa5ADt3dX2zYo+PWQLlwhfsagKrDaA=';

JWT::setKey($key);

echo JWT::encode(['id' => 333]);

var_dump(JWT::decode('eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJpZCI6MzMzfQ.GEXhj4DTByMfujtePe9Uv48ffpyBcsDRoD8sGCNH3eA'));