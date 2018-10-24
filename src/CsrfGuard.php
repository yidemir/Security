<?php

declare(strict_types=1);

namespace Demir\Security;

class CsrfGuard
{
  /**
   * Zaman aşımı süresini tutar
   *
   * @static integer
   */
  protected static $timeout = 900;

  /**
   * Jetonu tutar
   * 
   * @static string
   */
  protected static $token;

  /**
   * Session kontrolü yapar
   *
   * @throws \Exception
   * @return void
   */
  public static function boot() : void
  {
    if (empty(session_id())) {
      throw new \Exception('Oturum (Session) başlatılmamış');
    }
  }

  /**
   * HTML Input girdisi oluşturur
   *
   * @return string
   * @throws \Exception
   */
  public static function getField() : string
  {
    return '<input type="hidden" name="_CSRF_TOKEN" value="' . static::getToken() . '">';
  }

  /**
   * CSRF dizgeciği oluşturur
   *
   * @throws \Exception
   * @return string
   */
  public static function getToken() : string
  {
    static::boot();
    
    $_SESSION['_csrf']['time'] = time();
    $_SESSION['_csrf']['ip'] = $_SERVER['REMOTE_ADDR'];
    
    if (is_null(static::$token)) {
      static::$token = base64_encode(openssl_random_pseudo_bytes(32));
    }
    
    return $_SESSION['_csrf']['token'] = static::$token;
  }

  /**
   * CSRF dizgeciğini ve geçerliliğini test eder
   *
   * @param string $token
   * @throws \Exception
   * @return boolean
   */
  public static function checkToken(string $token = '')  : bool
  {
    static::boot();

    $token = $token === '' ? 
      (isset($_POST['_CSRF_TOKEN']) ? 
        $_POST['_CSRF_TOKEN'] : '') : $token;

    $result = static::checkTimeout() &&
      $_SESSION['_csrf']['token'] === $token &&
      $_SESSION['_csrf']['ip'] === $_SERVER['REMOTE_ADDR'];

    static::flush();

    return $result;
  }

  /**
   * Zaman aşımı değerini belirler
   *
   * @param integer $timeout
   * @return void
   */
  public static function setTimeout(int $timeout) : void
  {
    static::$timeout = $timeout;
  }

  /**
   * Zaman aşımına uğramış mı test eder
   *
   * @return boolean
   */
  protected static function checkTimeout() : bool
  {
    if (isset($_SESSION['_csrf']['time'])) {
      return ($_SERVER['REQUEST_TIME'] - $_SESSION['_csrf']['time']) < static::$timeout;
    }

    return false;
  }

  /**
   * CSRF bilgilerini temizler
   *
   * @return void
   */
  public static function flush() : void
  {
    unset($_SESSION['_csrf']);
  }
}
