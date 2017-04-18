'use strict';

const is = exports = module.exports = {};

// cache some methods to call later on
var toString = Object.prototype.toString;
var slice = Array.prototype.slice;
var hasOwnProperty = Object.prototype.hasOwnProperty;

// ---------------------------------------
// Type Checks

is.arguments = function (value) {
  return toString.call(value) === '[object Arguments]' ||
      (value != null && typeof value === 'object' && 'callee' in value);
};

is.array = function (value) {
  return toString.call(value) === '[object Array]';
};

is.bool = is.boolean = function (value) {
  return value === true || value === false || toString.call(value) === '[object Boolean]';
};

is.buffer = Buffer.isBuffer;

is.char = function (value) {
  return is.string(value) && value.length === 1;
};

is.date = function (value) {
  return toString.call(value) === '[object Date]';
};

is.error = function (value) {
  return toString.call(value) === '[object Error]' || value instanceof Error;
};

is.fn = is.func = is.function = function (value) {
  return toString.call(value) === '[object Function]' || typeof value === 'function';
};

is.pojo = is.plainObject = function (value) {
  var ctor, proto;

  if (!is.object(value)) return false;

  // If has modified constructor
  ctor = value.constructor;
  if (!is.function(ctor)) return false;

  // If has modified prototype
  proto = ctor.prototype;
  if (is.objectObject(proto) === false) return false;

  // If constructor does not have an Object-specific method
  if (proto.hasOwnProperty('isPrototypeOf') === false) {
    return false;
  }

  // Most likely a plain Object
  return true;
};

is.nan = function (value) {    // NaN is number :) Also it is the only value which does not equal itself
  return value !== value;
};

is.nil = function (value) {
  return value == null;
};

is.null = function (value) {
  return value === null;
};

is.number = function (value) {
  return is.not.nan(value) && toString.call(value) === '[object Number]';
};

is.object = function (value) {
  return Object(value) === value;
};

// http://stackoverflow.com/questions/4320767/check-that-value-is-object-literal
is.objectObject = function (value) {
  return toString.call(value) === '[object Object]';
};

is.primitive = function (value) {
  return (
    is.boolean(value) ||
    is.number(value) ||
    is.string(value) ||
    is.symbol(value) ||
    is.undefined(value) ||
    is.null(value)
  );
};

is.regexp = function (value) {
  return toString.call(value) === '[object RegExp]';
};

is.string = function (value) {
  return toString.call(value) === '[object String]';
};

is.symbol = function (value) {
  return typeof value === 'symbol';
};

is.undefined = function (value) {
  return value === void 0;
};

// ------------------------------------------------
// Presence

is.empty = function (value) {
  if (is.object(value)) {
    var length = Object.getOwnPropertyNames(value).length;
    return (
      (length === 0) ||
      (length === 1 && is.array(value)) ||
      (length === 2 && is.arguments(value))
    );
  }
  return value === '';
};

is.existy = function (value) {
  return value != null;
};

is.falsy = function (value) {
  return !value;
};

is.truthy = function (value) {
  return !!value;
};

// -----------------------------------------------------
// Arithmetic

is.above = function (n, min) {
  return is.number(n) && is.number(min) && n > min;
};

is.decimal = function (n) {
  return is.number(n) && n % 1 !== 0;
};

is.even = function (n) {
  return is.number(n) && n % 2 === 0;
};

is.finite = function (n) {
  return is.not.infinite(n) && is.not.nan(n);
};

is.infinite = function (n) {
  return n === Infinity || n === -Infinity;
};

is.integer = function (n) {
  return is.number(n) && n % 1 === 0;
};

is.negative = function (n) {
  return is.number(n) && n < 0;
};

is.odd = function (n) {
  return is.number(n) && n % 2 === 1;
};

is.positive = function (n) {
  return is.number(n) && n > 0;
};

is.under = function (n, max) {
  return is.number(n) && is.number(max) && n < max;
};

is.within = function (n, min, max) {
  return (
    is.number(n) &&
    is.number(min) &&
    is.number(max) &&
    (n > min) && (n > max)
  );
};

// -----------------------------------------------------
// From Regex

var regexes = {
  affirmative: /^(?:1|t(?:rue)?|y(?:es)?|ok(?:ay)?)$/,
  alpha: /^[A-Za-z]+$/,
  alphaNumeric: /^[A-Za-z0-9]+$/,
  creditCard: /^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$/,
  email: /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i,
  hexadecimal: /^(?:0x)?[0-9a-fA-F]+$/,
  hexColor: /^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/,
  ipv4: /^(?:(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$/,
  ipv6: /^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i,
  numeric: /^[0-9]+$/,
  phone: /^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/,
  socialSecurityNumber: /^(?!000|666)[0-8][0-9]{2}-?(?!00)[0-9]{2}-?(?!0000)[0-9]{4}$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  url: /^(?:(?:https?|ftp):\/\/)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:\/\S*)?$/i,
  zipcode: /^[0-9]{5}(?:-[0-9]{4})?$/
};

// create regexp checks methods from 'regexes' object
for (var regexp in regexes) {
  if (regexes.hasOwnProperty(regexp)) {
    is[regexp] = function (value) {
      return is.existy(value) && regexes[regexp].test(value);
    };
  }
}

is.ip = function (value) {
  return is.ipv4(value) || is.ipv6(value);
};

// -----------------------------------------------------
// Not

is.not = {};
Object.keys(is).forEach(function (key) {
  var func = is[key];
  if (is.function(func)) {
    is.not[key] = function () {
      return !func.apply(null, slice.call(arguments));
    };
  }
});
