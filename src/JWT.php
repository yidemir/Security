<?php

declare(strict_types=1);

namespace Demir\Security;

class JWT
{
  /**
   * Gizli anahtarı tutar
   * 
   * @static string
   */
  protected static $key;

  /**
   * Şifreleme algoritmasının tipini tutar
   * 
   * @static string
   */
  protected static $algo = 'HS256';

  /**
   * Anahtarın durumunu kontrol eder
   *
   * @throws \Exception
   * @return void
   */
  protected static function boot() : void
  {
    if (is_null(static::$key)) {
      throw new \Exception('Gizli anahtar belirlenmemiş');
    }
  }

  /**
   * Anahtarı belirler
   * 
   * @param string $key
   * @return void
   */
  public static function setKey(string $key) : void
  {
    static::$key = $key;
  }

  /**
   * Algoritma tipini belirler
   * 
   * @param string
   * @return void
   */
  public static function setAlgo(string $algo) : void
  {
    static::$algo = $algo;
  }

  /**
   * Veriyi şifreler
   *
   * @throws \Exception
   * @param array $payload
   * @return string
   */
  public static function encode(array $payload) : string
  {
    static::boot();
    $header = ['type' => 'JWT', 'alg' => static::$algo];
    $segments = [];
    $segments[] = static::base64Encode(static::jsonEncode($header));
    $segments[] = static::base64Encode(static::jsonEncode($payload));
    $input = implode('.', $segments);
    $signature = static::sign($input);
    $segments[] = static::base64Encode($signature);

    return implode('.', $segments);
  }

  /**
   * Veriyi çözer
   *
   * @throws \Exception
   * @param string jwt
   * @return mixed
   */
  public static function decode(string $jwt)
  {
    static::boot();
    $segments = explode('.', $jwt);

    if (count($segments) !== 3) {
      throw new \Exception('Geçersiz JWT, parçalar yanlış');
    }

    [$header64, $payload64, $signature64] = $segments;

    $header = static::base64Decode($header64);
    if (($header = static::jsonDecode($header)) === null) {
      throw new \Exception('Parça çözülemedi');
    }

    $payload = static::base64Decode($payload64);
    if (($payload = static::jsonDecode($payload)) === null) {
      throw new \Exception('Parça çözülemedi');
    }

    $signature = static::base64Decode($signature64);

    if (!isset($header->alg)) {
      throw new \Exception('Algoritma eksik');
    }

    if (empty($header->alg)) {
      throw new \Exception('Algoritma eksik');
    }

    if ($signature !== static::sign("{$header64}.{$payload64}")) {
      throw new \Exception('İmza doğrulaması başarısız');
    }

    return $payload;
  }

  /**
   * @param string $data
   * @throws \Exception
   * @return string
   */
  protected static function sign(string $data) : string
  {
    $methods = [
      'HS256' => 'sha256',
      'HS384' => 'sha384',
      'HS512' => 'sha512',
    ];

    if (!key_exists(static::$algo, $methods)) {
      throw new \Exception('Algoritma desteklenmiyor');
    }

    return hash_hmac($methods[static::$algo], $data, static::$key, true);
  }

  /**
   * @param string $input
   * @throws \Exception
   * @return mixed
   */
  protected static function jsonDecode(string $input)
  {
    $object = json_decode($input);

    if (function_exists('json_last_error') && $error = json_last_error()) {
      static::handleJsonError($error);
    } else if ($object === null) {
      throw new \Exception('Girdi geçersiz');
    }

    return $object;
  }


  /**
   * @param array $input
   * @throws \Exception
   * @return string
   */
  protected static function jsonEncode(array $input) : string
  {
    $json = json_encode($input);

    if (function_exists('json_last_error') && $error = json_last_error()) {
      static::handleJsonError($error);
    } else if (is_null($json)) {
      throw new \Exception('Girdi geçersiz');
    }

    return $json;
  }

  /**
   * @param string $input
   * @return mixed
   */
  protected static function base64Decode(string $input)
  {
    $remainder = strlen($input) % 4;

    if ($remainder) {
      $padlen = 4 - $remainder;
      $input .= str_repeat('=', $padlen);
    }

    return base64_decode(strtr($input, '-_', '+/'));
  }

  /**
   * @param string $input
   * @return string
   */
  protected static function base64Encode(string $input)
  {
    return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
  }

  /**
   * @param int $error
   * @throws \Exception
   * @return void
   */
  protected static function handleJsonError(int $error) : void
  {
    $messages = [
      JSON_ERROR_DEPTH => 'Maksimum yığın derinliği aşıldı',
      JSON_ERROR_CTRL_CHAR => 'Beklenmeyen kontrol karakteri bulundu',
      JSON_ERROR_SYNTAX => 'Sözdizimi hatası, hatalı biçimlendirilmiş JSON'
    ];

    throw new \Exception(
      key_exists($error, $messages) ? $messages[$error] : "Bilinmeyen JSON hatası '{$error}'"
    );
  }
}