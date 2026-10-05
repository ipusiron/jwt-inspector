// サンプルのトークンと鍵。globalThis.JwtSamples に置く
// 鍵はこのツールのデモ用に作ったもの（本番の鍵ではない）。署名は Node の crypto で付けた
// 作り方は ipusiron-work の business/research/try100_audit/ref/day053/make_samples.mjs
(() => {
  'use strict';

  globalThis.JwtSamples = {
    "decode": {
      "valid": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjQxMDI0NDQ4MDAsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9.ZVBM1O2HiSr_Nu8VJ7SONE64u5yZVSNnoIzYyI0rjv0",
      "expired": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjIsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9.pY7t5_daf8s8MzJJa_aO23fkUqp6L3qbrUbgqAAk78U",
      "none": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEyMzQiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6NDEwMjQ0NDgwMH0.",
      "risky": "eyJ0eXAiOiJKV1QiLCJraWQiOiIuLi8uLi8uLi8uLi9kZXYvbnVsbCIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuZXhhbXBsZS9qd2tzLmpzb24iLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjQxMDI0NDQ4MDAsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9._jrtml9dlRfWRFoy4lhHJbuCaPoeqCYzR5xueRiFXxA"
    },
    "verify": {
      "HS256": {
        "alg": "HS256",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjQxMDI0NDQ4MDAsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9.ZVBM1O2HiSr_Nu8VJ7SONE64u5yZVSNnoIzYyI0rjv0",
        "key": "jwt-inspector-demo-key-0123456789abcdef-0123456789abcdef01234567"
      },
      "RS256": {
        "alg": "RS256",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjQxMDI0NDQ4MDAsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9.P5aSfMm8FtZm0ijemPJb6G4vOWUCyYzkA86XlHwV8jbOA_yYFNXqyPTm0Y01UD5Z2BxfqmyU31TXYfi6Drb1DOUUUx4F4A54b8S9nlqKeX173wqTUQUyMKlXOZ2myjsnd-XwB2mc1FXYkJ1Zsfmb7bo1j3xsriMVDSK6l3rdkcC_rBt6HaXKUc9_6-URMYHvnpdIgTxqEk7p9z4od7ca_OIjIErPdVOy0BGtm0qvWUd2wUPVRRQo1mcUnY-Ru17jHaPFVO47Buz35epDajNqUEpPVKj1NVMHEJ8MAPd_J_f3cjZwPj-7bn0XivxCqcPf1odc6qt2mLN0h7qb-gUXDw",
        "key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuBhmsiKs058gFbD0nhCq\n05oPY5aSdziEZGYBzde1YF+OUjL9yUaQ+3c+LGbrjIa4Jy/3KUpg3OUpz43tuppZ\nkgMNtZhJTwyVZfQ44N5mReJeJnnewbItSMPeUrP+xu95b2s5WDP3OUisutkfXkUo\nmiCXZvCtdnBGjJz8Z3jhxKu4xMbTXWF+3ZM9r6/lDt1nsLzUwnd2M+ID+gEvl1YL\nyngESpapt64YXYGImu4jCL0eQf1S9hvHAFgDDSYd5MtPklB0faHO6NMPQrB7m5vp\na8k8UImMnIhuPk5Ycvw6FH6Ca0HEvup1EMVW52At3NLxh8MGKOe6aV2f01R+/Px1\nqwIDAQAB\n-----END PUBLIC KEY-----"
      },
      "PS256": {
        "alg": "PS256",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjQxMDI0NDQ4MDAsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9.ie6QWDaEBO8VHTrwV0DyLdekouyNz7WN6C9avnQgRV2hDtmXXNxLE_UA6HHBOn4bg6CRK_focyEvEv5Jfr3lV3LTq99bjoiSELrgeWKx1V3cCvXMYWZr370zf5253WTeZqK4Y2RCcA1AGS7KeUD2WFMIUJ9C1JPrVlLlDXO3oMvHcQbZ36Pzx6u5RlKE4ZjSyms7kb9UlXiO1tW3M8QAEh_2fUWsoSxZsGsRaY8Ecc5s5_3UbTscVss51OLiOnyQ2CKloNFNMuxvsFfkW3uNh-ZsrrSXvrkx4Qrpd1wtgNVl6PeZTCh7tyq6kIK7wCbR0KTYs1xW4bSamVYf5X0Ifg",
        "key": "{\"kty\":\"RSA\",\"n\":\"uBhmsiKs058gFbD0nhCq05oPY5aSdziEZGYBzde1YF-OUjL9yUaQ-3c-LGbrjIa4Jy_3KUpg3OUpz43tuppZkgMNtZhJTwyVZfQ44N5mReJeJnnewbItSMPeUrP-xu95b2s5WDP3OUisutkfXkUomiCXZvCtdnBGjJz8Z3jhxKu4xMbTXWF-3ZM9r6_lDt1nsLzUwnd2M-ID-gEvl1YLyngESpapt64YXYGImu4jCL0eQf1S9hvHAFgDDSYd5MtPklB0faHO6NMPQrB7m5vpa8k8UImMnIhuPk5Ycvw6FH6Ca0HEvup1EMVW52At3NLxh8MGKOe6aV2f01R-_Px1qw\",\"e\":\"AQAB\"}"
      },
      "ES256": {
        "alg": "ES256",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjQxMDI0NDQ4MDAsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9.IRjOBViRq42ZDmdW7rUUKFB-v8v2CJspeDhyVGWtKFXXhZUBGbjClRuI8cBMpuVTCBS2mfdSgkF_NWu3qxst4w",
        "key": "{\"kty\":\"EC\",\"x\":\"hyCFj-CDDRU8ENuQCxq7rXtWvyI4m5xQFiJRpoymL5A\",\"y\":\"aJ2sPbIwOcPNZ5lmjPzLOq-KyKwPO8-40i7cslLhT84\",\"crv\":\"P-256\"}"
      },
      "weak": {
        "alg": "HS256",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjM0IiwiYXVkIjoiand0LWluc3BlY3Rvci1kZW1vIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjQxMDI0NDQ4MDAsIm5hbWUiOiJEZW1vIFVzZXIiLCJyb2xlIjoidXNlciJ9.9kJWiqViBeHXRc8GAboluctrwjInfv4bk0eTviChwOM",
        "key": "secret"
      }
    }
  };
})();
