<?php
/**
 * A JWT library for PHP.
 * Created by van23qf.
 * User: van23qf
 * Email: qf19910623@gmail.com
 * Date: 2019/5/30/0030 9:50
 */

namespace Van23qf\PHPJwt;


class Jwt
{

    public $alg = 'sha256';

    public $secret;

    public $error;

    public $data;

    /**
     * Jwt constructor.
     * @param $secret
     */
    public function __construct($secret) {
        $this->secret = $secret;
    }

    /**
     * @param $data
     * @param string $alg
     * @return string
     */
    public function makeJwt($data, $alg = 'sha256') {
        $this->alg = $alg;
        $header = json_encode(array('alg'=>$this->alg, 'typ'=>'JWT'));
        $payloadArr = $data;
        $payload = json_encode($payloadArr);
        $signature = $this->makeSignature($header, $payload);
        return $this->base64UrlEncode($header).'.'.$this->base64UrlEncode($payload).'.'.$signature;
    }

    /**
     * @param $jwtStr
     * @return bool
     */
    public function checkJwt($jwtStr) {
        $decodeArr = $this->decodeJwt($jwtStr);
        if (!$decodeArr) {
            return false;
        }
        $header = json_decode($decodeArr['header'], true);
        $payload = json_decode($decodeArr['payload'], true);
        $signature = $decodeArr['signature'];
        if (!$header['alg']) {
            $this->error = 'Algorithm Params Missing';
            return false;
        }
        $this->alg = $header['alg'];
        if ($signature != $this->makeSignature($decodeArr['header'], $decodeArr['payload'])) {
            $this->error = 'Signature Error';
            return false;
        }
        $this->data = $payload;
        return true;
    }

    /**
     * @param $jwtStr
     * @return array|bool
     */
    public function decodeJwt($jwtStr) {
        $explodeArr = explode('.', $jwtStr);
        if (!$explodeArr[0] || !$explodeArr[1] || !$explodeArr[2]) {
            $this->error = 'Format Error';
            return false;
        }
        $header = $this->base64UrlDecode($explodeArr[0]);
        $payload = $this->base64UrlDecode($explodeArr[1]);
        $signature = $explodeArr[2];
        if (!$header || !$payload || !$signature) {
            $this->error = 'Decode Fail';
            return false;
        }
        return array(
            'header'    =>  $header,
            'payload'    =>  $payload,
            'signature'    =>  $signature
        );
    }

    /**
     * @param $header
     * @param $payload
     * @return string
     */
    public function makeSignature($header, $payload) {
        return hash_hmac($this->alg, $this->base64UrlEncode($header).".".$this->base64UrlEncode($payload), $this->secret);
    }

    /**
     * @param $header
     * @param $payload
     * @param $outSignature
     * @return bool
     */
    public function checkSignature($header, $payload, $outSignature) {
        return $outSignature == $this->makeSignature($header, $payload);
    }

    /**
     * @param $str
     * @return mixed
     */
    public function base64UrlEncode($str) {
        return str_replace(array("=", "+", "/"), array("", "-", "_"), base64_encode($str));
    }

    /**
     * @param $str
     * @return bool|string
     */
    public function base64UrlDecode($str) {
        return base64_decode(str_replace(array("-", "_"), array("+", "/"), $str));
    }

}