<?php

use Demir\Security\Validation;

require __DIR__ . '/../vendor/autoload.php';

$validation = new Validation([
  'username' => 'yidemir',
  'password' => 'secret',
  'password_confirmation' => 'secret',
  'email' => 'foo@bar.com',
  'age' => 30,
  'text' => 'Lorem lipsum dolor sit amet',
  'price' => '250.50',
  'datetime' => '2018-05-05 23:12:54',
  'ip' => '125.12.64.12',
  'website' => 'https://yilmazdemir.com.tr',
  'category' => 'news'
]);

$validation
  ->field('username', 'Kullanıcı adı')->validate('required|alnum')
  ->field('password', 'Şifre')->validate('required|same:password_confirmation')
  ->field('password_confirmation', 'Şifre Tekrarı')->validate('required')
  ->field('email', 'E-posta')->validate('required|email')
  ->field('age', 'Yaş')->validate('required|numeric|max:65|min:18')
  ->field('text', 'İçerik')->validate('required|maxlen:255|minlen:10')
  ->field('price', 'Fiyat')->validate('required|float')
  ->field('datetime', 'Tarih')->validate('required|time')
  ->field('ip', 'IP Adresi')->validate('required|ip')
  ->field('website', 'Web Adresi')->validate('required|url')
  ->field('category', 'Kategori')->validate('required|in:news,magazine');

if ($validation->fails()) {
  echo '<p>Bir validasyon hatası meydana geldi</p>';
  echo $validation->getErrorsAsString();
} else {
  echo 'Her şey yolunda!';
}