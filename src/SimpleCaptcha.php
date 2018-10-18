<?php

declare(strict_types=1);

namespace Demir\Security;

class SimpleCaptcha
{
  /**
   * Gösterilecek karakter uzunluğu
   * 
   * @var integer
   */
  private $length = 7;

  /**
   * Gösterilecek karakterler
   * 
   * @var string
   */
  private $chars = 'abcdefghijklmnoprstuvyzABCDEFGHIJKLMOPRSTUVYZ1234567890';

  /**
   * Geçerli resim boyutu
   * 
   * @var array
   */
  private $imgSize = [130, 40];

  /**
   * Gösterilecek rastgele dizge
   * 
   * @var string
   */
  private $string = null;

  /**
   * Sınıf başlatıcı
   * 
   * @param integer $length
   * @param string $chars
   * @throws \Exception
   */
  public function __construct(?int $length = null, ?string $chars = null)
  {
    if (empty(session_id())) {
      throw new \Exception('Oturum (Session) başlatılmamış');
    }

    $this->length = is_null($length) ? $this->length : $length;
    $this->chars = is_null($chars) ? $this->chars : $chars;
  }

  /**
   * Resimi gösteren metod
   * 
   * @param array $imgSize Resim boyutu
   * @param integer $fontSize Font boyutu, maksimum 5
   * @return void
   */
  public function showImage(array $imgSize = [], int $fontSize = 5) : void
  {
    $this->generate();
    $this->imgSize = empty($imgSize) ? $this->imgSize : $imgSize;

    $width = $this->imgSize[0];
    $height = $this->imgSize[1];
    $im = imagecreate($width, $height);

    imagecolorallocate($im, 255, 255, 255);
    $color = imagecolorallocate($im, mt_rand(0, 255), mt_rand(0,50), mt_rand(200,255));

    $fontWidth = imagefontwidth($fontSize);
    $fontHeight = imagefontheight($fontSize);

    $textWidth = $fontWidth * strlen($this->string);
    $positionCenter = ceil(($width - $textWidth) / 2);

    $textHeight = $fontHeight;
    $positionMiddle = ceil(($height - $textHeight) / 2);

    imagestring(
      $im, $fontSize, intval($positionCenter), intval($positionMiddle), $this->string, $color
    );

    header('Content-type: image/gif');
    imagegif($im);
    imagedestroy($im);
  }

  /**
   * Dizge oluşturur
   */
  public function generate() : void
  {
    for ($p = 0; $p < $this->length; $p++) {
      $this->string .= $this->chars[mt_rand(0, strlen($this->chars) - 1)];
    }

    $_SESSION['_captcha'] = $this->string;
  }

  /**
   * Dizgeyi doğrular
   * 
   * @param string $string
   * @return boolean
   */
  public function validate(?string $string = null) : bool
  {
    $string = is_null($string) ? $_POST['captcha'] : $string;
    $valid = $string == $_SESSION['_captcha'];
    $this->generate();
    return $valid;
  }
}