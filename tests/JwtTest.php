<?php
/**
 * Created by van23qf.
 * User: van23qf
 * Email: qf19910623@gmail.com
 * Date: 2019/5/30/0030 10:31
 */

namespace Van23qf\Jwt\jwt;


class JwtTest extends \PHPUnit_Framework_TestCase
{

    public function testMakeJwt() {
        $data = array();
        $data['uid'] = '111';
        $data['username'] = 'test001';
        $secret = '123456';
        $jwt = new Jwt($secret);
        echo $jwt->makeJwt($data, 'sha256');
    }

    public function testCheckJwt() {
        $jwtstr = "eyJhbGciOiJzaGEyNTYiLCJ0eXAiOiJKV1QifQ.eyJ1aWQiOiIxMTEiLCJ1c2VybmFtZSI6InRlc3QwMDEiLCJpYXQiOjE1NTkxOTUzMDAsIm5iZiI6MTU1OTE5NTMwMCwiZXhwIjowfQ.233bed345976da63734f26e2efee9843c9d18cce876cbcd788684c28820233a5";
        $secret = '123456';
        $jwt = new Jwt($secret);
        $this->assertTrue($jwt->checkJwt($jwtstr));
        print_r($jwt->data);
    }

    public function testDecodeJwt() {
        $jwtstr = "eyJhbGciOiJzaGEyNTYiLCJ0eXAiOiJKV1QifQ.eyJ1aWQiOiIxMTEiLCJ1c2VybmFtZSI6InRlc3QwMDEiLCJpYXQiOjE1NTkxOTUzMDAsIm5iZiI6MTU1OTE5NTMwMCwiZXhwIjowfQ.233bed345976da63734f26e2efee9843c9d18cce876cbcd788684c28820233a5";
        $secret = '123456';
        $jwt = new Jwt($secret);
        print_r($jwt->decodeJwt($jwtstr));
    }

    public function testBase64UrlEncode() {
        $str = 'hello world!';
        $jwt = new Jwt('');
        echo $jwt->base64UrlEncode($str);
    }

    public function testBase64UrlDecode() {
        $str = 'hello world!';
        $jwt = new Jwt('');
        $encodestr = $jwt->base64UrlEncode($str).'==';
        echo $jwt->base64UrlDecode($encodestr);
    }

    public function testMakeSignature() {
        $header = '111';
        $payload = '222';
        $secret = '123456';
        $jwt = new Jwt($secret);
        $jwt->alg = 'sha256';
        echo $jwt->makeSignature($header, $payload);
    }

    public function testCheckSignature() {
        $header = '111';
        $payload = '222';
        $secret = '123456';
        $jwt = new Jwt($secret);
        $jwt->alg = 'sha256';
        $outSignature = $jwt->makeSignature($header, $payload);
        $this->assertTrue($jwt->checkSignature($header, $payload, $outSignature), '签名错误');
    }


}
