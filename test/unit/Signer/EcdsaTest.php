<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Keys;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
final class EcdsaTest extends \PHPUnit\Framework\TestCase
{
    use Keys;

    /**
     * @return Ecdsa
     */
    private function getSigner(): Ecdsa
    {
        $signer = $this->getMockForAbstractClass(Ecdsa::class);

        $signer->method('getAlgorithm')
               ->willReturn('sha256');

        $signer->method('getAlgorithmId')
               ->willReturn('ES256');

        return $signer;
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::sign
     */
    public function signShouldReturnAHashUsingPrivateKey(): void
    {
        $signer = $this->getSigner();
        $key    = self::$ecdsaKeys['private'];

        self::assertInternalType('string', $signer->sign('testing', $key));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::verify
     */
    public function verifyShouldDelegateToEcdsaSignerUsingPublicKey(): void
    {
        $payload    = 'testing';
        $privateKey = \openssl_get_privatekey(self::$ecdsaKeys['private-params']->getContent());
        $signature  = '';
        \openssl_sign($payload, $signature, $privateKey, \OPENSSL_ALGO_SHA256);

        $signer      = $this->getSigner();
        $key         = self::$ecdsaKeys['public-params'];

        self::assertTrue($signer->verify($signature, 'testing', $key));
    }
}
