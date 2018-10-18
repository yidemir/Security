<?php

declare(strict_types=1);

namespace Demir\Security;

class Validation
{
  /**
   * Validasyon kurallarını tutar
   *
   * @var array
   */
  protected $validations = [];

  /**
   * Validasyondan geçecek değerleri tutar
   * 
   * @var array
   */
  protected $values = [];

  /**
   * Kuralları tutar
   * 
   * @var array
   */
  protected $rules = [];

  /**
   * Validasyondan geçtikten sonra oluşan hataları tutar
   * 
   * @var array
   */
  protected $errors = [];

  /**
   * Hata mesajlarını tutar
   * 
   * @var array
   */
  protected $messages = [];

  /**
   * İşlem görecek olan alan adı
   * 
   * @var string
   */
  protected $field;

  /**
   * İşlem görecek olan alan başlığı
   * 
   * @var array
   */
  protected $title;

  /**
   * Kendi örneğini tutar
   * 
   * @static Validation
   */
  protected static $instance;

  /**
   * Sınıf yapıcısı
   * 
   * @var array $values
   */
  public function __construct(array $values = [])
  {
    $this->values = $values;
    $this->create();
    static::$instance = $this;
  }

  /**
   * Validasyon kurallarını ve mesajlarını oluşturur
   * 
   * @return void
   */
  protected function create() : void
  {
    $this->validations = [
      'required' => function() : bool {
        return $this->hasField();
      },
      'email' => function() : bool {
        if ($this->hasField()) {
          return (bool) filter_var($this->getField(), FILTER_VALIDATE_EMAIL);
        }

        return true;
      },
      'same' => function($otherField) : bool {
        if ($this->hasField()) {
          return $this->getField() === $this->getField($otherField);
        }

        return true;
      },
      'maxlen' => function($maxlen) : bool {
        if ($this->hasField()) {
          return mb_strlen($this->getField()) <= $maxlen;
        }

        return true;
      },
      'minlen' => function($minlen) : bool {
        if ($this->hasField()) {
          return mb_strlen($this->getField()) >= $minlen;
        }

        return true;
      },
      'max' => function($max) : bool {
        if ($this->hasField()) {
          return $this->getField() <= $max;
        }

        return true;
      },
      'min' => function($min) : bool {
        if ($this->hasField()) {
          return $this->getField() >= $min;
        }

        return true;
      },
      'float' => function() : bool {
        if ($this->hasField()) {
          return (bool) filter_var($this->getField(), FILTER_VALIDATE_FLOAT);
        }

        return true;
      },
      'numeric' => function() : bool {
        if ($this->hasField()) {
          return is_numeric($this->getField());
        }

        return true;
      },
      'alpha' => function() : bool {
        if ($this->hasField()) {
          return ctype_alpha($this->getField());
        }

        return true;
      },
      'alnum' => function() : bool {
        if ($this->hasField()) {
          return ctype_alnum($this->getField());
        }

        return true;
      },
      'time' => function() : bool {
        if ($this->hasField()) {
          $dateArray = date_parse($this->getField());
          return $dateArray['error_count'] <= 0;
        }

        return true;
      },
      'ip' => function() : bool {
        if ($this->hasField()) {
          return (bool) filter_var($this->getField(), FILTER_VALIDATE_IP);
        }

        return true;
      },
      'url' => function() : bool {
        if ($this->hasField()) {
          return (bool) filter_var($this->getField(), FILTER_VALIDATE_URL);
        }

        return true;
      },
      'regex' => function(string $regex) : bool {
        if ($this->hasField()) {
          return (bool) preg_match($regex, $this->getField());
        }

        return true;
      },
      'lower' => function() : bool {
        if ($this->hasField()) {
          return ctype_lower($this->getField());
        }

        return true;
      },
      'upper' => function() : bool {
        if ($this->hasField()) {
          return ctype_upper($this->getField());
        }

        return true;
      },
      'in' => function(string $items) : bool {
        $items = explode(',', $items);
        if ($this->hasField()) {
          return in_array($this->getField(), $items);
        }

        return true;
      },
      'notin' => function(string $items) : bool {
        $items = explode(',', $items);
        if ($this->hasField()) {
          return !in_array($this->getField(), $items);
        }

        return true;
      }
    ];

    $this->messages = [
      'required' => '%s alanı gereklidir',
      'email' => '%s alanı bir e-posta adresi değil',
      'same' => '%s alanı diğer alanla aynı değere sahip olmalıdır',
      'maxlen' => '%s alanı çok uzun',
      'minlen' => '%s alanı çok kısa',
      'max' => '%s alanı çok fazla',
      'min' => '%s alanı çok az',
      'float' => '%s alanı geçerli bir ondalık sayı olmalıdır',
      'numeric' => '%s alanı yalnızca rakamlardan oluşabilir',
      'alpha' => '%s alanı yalnızca harflerden oluşabilir',
      'alnum' => '%s alanı yalnızca harf ve rakamlardan oluşabilir',
      'time' => '%s alanı geçerli bir zaman değeri olmalıdır',
      'ip' => '%s alanı geçerli bir IP adresi olmalıdır',
      'url' => '%s alanı geçerli bir URL olmalıdır',
      'regex' => '%s alanı geçerli değil',
      'lower' => '%s alanı yalnızca küçük harflerden oluşmalıdır',
      'upper' => '%s alanı yalnızca büyük harflerden oluşmalıdır',
      'in' => '%s alanı belirlenen öğelerden birisi olmalıdır',
      'notin' => '%s alan belirlenen öğelerden birisi olmamalıdır'
    ];
  }

  /**
   * Sınıf örneğini döndürür
   *
   * @return static
   */
  public static function getInstance()
  {
    if (is_null(static::$instance)) {
      static::$instance = new static();
    }

    return static::$instance;
  }

  /**
   * Alanın geçerli olup olmadığını sorgular
   * 
   * @param string|null $name
   * @return bool
   */
  protected function hasField(?string $name = null) : bool
  {
    if (is_null($name)) {
      return isset($this->values[$this->field]) &&
        !empty(trim((string) $this->values[$this->field]));
    }

    return isset($this->values[$name]) &&
      !empty(trim((string) $this->values[$name]));
  }

  /**
   * Alanın değerini döndürür
   *
   * @var string|null $name
   * @return mixed
   */
  protected function getField(?string $name = null)
  {
    if (is_null($name)) {
      return $this->values[$this->field];
    }

    return $this->values[$name];
  }

  /**
   * Değerleri sınıfa tanımlar
   *
   * @param array $values
   * @return Validation
   */
  public function values(array $values) : Validation
  {
    $this->values = array_merge($this->values, $values);
    return $this;
  }

  /**
   * Validasyondan geçirilecek alanı tanımlar
   *
   * @param string name
   * @param string $title
   * @return Validation
   */
  public function field(string $name, string $title) : Validation
  {
    $this->field = $name;
    $this->title = $title;
    
    return $this;
  }

  /**
   * Validasyonu başlatır
   *
   * @param array $validations
   * @throws \Exception
   * @return Validation
   */
  public function validate($validations) : Validation
  {
    if (is_null($this->field)) {
      throw new \Exception('Validasyondan geçirilecek öğe belirlenmemiş');
    }

    $validations = is_string($validations) ?
      explode('|', $validations) : $validations;

    foreach ($validations as $validation) {
      $validation = explode(':', $validation);
      $rule = array_shift($validation);
      $parameter = implode('', $validation);
      $this->check($rule, $parameter);
    }

    $this->field = null;
    $this->title = null;

    return $this;
  }

  /**
   * Test eder
   *
   * @param string $rule
   * @param string $parameter
   * @throws \Exception
   * @throws \InvalidArgumentException
   * @return void
   */
  protected function check(string $rule, string $parameter = '') : void
  {
    if (isset($this->validations[$rule]) && $this->validations[$rule] instanceof \Closure) {
      $check = $this->validations[$rule]->call($this, $parameter);

      if ($check === false) {
        if (isset($this->messages[$rule])) {
          $error = sprintf($this->messages[$rule], $this->title, $parameter);
        } else {
          throw new \Exception('Bu validasyon için hata mesajı tanımlanmamış: ' . $rule);
        }

        $this->errors[] = $error;
        $this->errors['fields'][$this->field] = $error;
      }
    } else {
      throw new \InvalidArgumentException("Böyle bir kural yok: '{$rule}'");
    }
  }

  /**
   * Hata mesajlarını döndürür
   *
   * @return array
   */
  public function getErrors() : array
  {
    $fields = isset($this->errors['fields']) ?
      $this->errors['fields'] : [];
    unset($this->errors['fields']);
    $errors = $this->errors;
    $this->errors['fields'] = $fields;

    return $errors;
  }

  /**
   * Validasyon geçersiz mi kontrol eder
   *
   * @return boolean
   */
  public function fails() : bool
  {
    return !$this->success();
  }

  /**
   * Validasyon geçerli mi kontrol eder
   *
   * @return boolean
   */
  public function success() : bool
  {
    return empty($this->getErrors());
  }

  /**
   * Alana özel hata mesajı döndürür
   *
   * @param string $field
   * @return string|null
   */
  public function getError(string $field) : ?string
  {
    return isset($this->errors['fields'][$field]) ?
      $this->errors['fields'][$field] : null;
  }

  /**
   * Hata mesajlarını dizge biçiminde döndürür
   *
   * @return string
   */
  public function getErrorsAsString() : string
  {
    return implode('<br>', $this->getErrors());
  }

  /**
   * Yeni bir validasyon ekler
   *
   * @param string $rule
   * @param \Closure $callback
   * @param string $message
   * @return Validation
   */
  public function setValidation(
    string $rule, 
    \Closure $callback, 
    string $message
  ) : Validation
  {
    $this->validations[$rule] = $callback;
    $this->messages[$rule] = $message;
    return $this;
  }

  /**
   * Hata mesajı ekler veya varsa düzenler
   *
   * @param string $rule
   * @param string $message
   * @return Validation
   */
  public function setMessage(string $rule, string $message) : Validation
  {
    $this->messages[$rule] = $message;
    return $this;
  }
}