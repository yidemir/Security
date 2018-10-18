<?php

declare(strict_types=1);

namespace Demir\Security;

class Crypt
{
  /**
   * Gizli anahtar dizgesini tutar
   * 
   * @var string
   */
  private $secret;

  /**
   * Şifreleme metodunu tutar
   * 
   * @var string
   */
  private $cipherMethod;

  /**
   * Ayırıcıyı tutar
   * 
   * @var string
   */
  private $separator;

  /**
   * IV uzunluğunu tutar
   * 
   * @var int
   */
  private $ivLength;

  /**
   * Kendi örneğini tutar
   * 
   * @static Crypt
   */
  private static $instance;

  /**
   * Sınıf başlatıcı
   *
   * @param string $secret
   * @param string $cipherMethod
   * @param string $separator
   */
  public function __construct(
    string $secret,
    string $cipherMethod = 'AES-256-CBC',
    string $separator = '::'
  ) {
    $this->secret = $secret;
    $this->cipherMethod = $cipherMethod;
    $this->separator = $separator;
    $this->ivLength = openssl_cipher_iv_length($cipherMethod);
  }

  /**
   * Gizli anahtarı döndürür
   * 
   * @return string
   */
  public function getSecret() : string
  {
    return $this->secret;
  }

  /**
   * Şifreler/kriptolar
   * 
   * @param string $data
   * @return string
   */
  public function encrypt(string $data) : string
  {
    $decodedKey = base64_decode($this->secret);
    $iv = base64_encode(openssl_random_pseudo_bytes($this->ivLength));
    $iv = substr($iv, 0, $this->ivLength);
    $encryptedData = openssl_encrypt($data, $this->cipherMethod, $decodedKey, 0, $iv);

    return base64_encode($encryptedData.$this->separator.$iv);
  }

  /**
   * Şifreyi çözer
   * 
   * @param string $data
   * @return string
   */
  public function decrypt(string $data) : string
  {
    $decodedKey = base64_decode($this->secret);
    $explode = explode($this->separator, base64_decode($data), 2);
    if (count($explode) !== 2) return '';
    [$encryptedData, $iv] = $explode;
    $iv = substr($iv, 0, $this->ivLength);

    return openssl_decrypt($encryptedData, $this->cipherMethod, $decodedKey, 0, $iv);
  }

  /**
   * Sınıf örneğini döndürür
   * 
   * @throws \Exception
   * @return Crypt
   */
  public function getInstance()
  {
    if (is_null(static::$instance)) {
      throw new \Exception('Crypt sınıfı başlatılmamış');
    }

    return static::$instance;
  }
}