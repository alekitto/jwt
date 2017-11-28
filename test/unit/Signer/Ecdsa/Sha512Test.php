<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
final class Sha512Test extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::create
     * @covers \Lcobucci\JWT\Signer\Ecdsa::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @uses \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @uses \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     */
    public function createShouldReturnAValidInstance(): void
    {
        self::assertInstanceOf(Sha512::class, Sha512::create());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        self::assertEquals('ES512', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        self::assertEquals('sha512', $this->getSigner()->getAlgorithm());
    }

    private function getSigner(): Sha512
    {
        return new Sha512();
    }
}
