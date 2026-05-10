<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth\Tests;

use Cbox\CboxIdJwksAuth\Exceptions\InvalidTokenException;
use Cbox\CboxIdJwksAuth\JwksFetcher;
use Cbox\CboxIdJwksAuth\JwksValidator;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

const JWKS_URI = 'https://id.test/.well-known/jwks.json';
const ISSUER = 'https://id.test';
const AUDIENCE = 'vault.cbox.systems';

beforeEach(function (): void {
    Cache::flush();
});

/**
 * Generate an RSA keypair, return [privatePEM, publicPEM, kid].
 */
function makeRsaKeypair(string $kid = 'test-kid-1'): array
{
    $resource = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    openssl_pkey_export($resource, $privatePem);
    $details = openssl_pkey_get_details($resource);

    return [$privatePem, $details['key'], $kid, $details['rsa']];
}

/**
 * Convert a public key's modulus + exponent (binary) to JWK form.
 */
function rsaPublicToJwk(array $rsa, string $kid): array
{
    return [
        'kty' => 'RSA',
        'kid' => $kid,
        'use' => 'sig',
        'alg' => 'RS256',
        'n' => rtrim(strtr(base64_encode($rsa['n']), '+/', '-_'), '='),
        'e' => rtrim(strtr(base64_encode($rsa['e']), '+/', '-_'), '='),
    ];
}

function fakeJwks(array $jwks): void
{
    Http::fake([
        JWKS_URI => Http::response(['keys' => $jwks], 200),
    ]);
}

function mintToken(string $privatePem, string $kid, array $claims): string
{
    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText($privatePem),
        InMemory::plainText('placeholder'),
    );

    $now = new \DateTimeImmutable;

    $builder = $config->builder()
        ->withHeader('kid', $kid)
        ->issuedBy($claims['iss'] ?? ISSUER)
        ->permittedFor(...(array) ($claims['aud'] ?? [AUDIENCE]))
        ->relatedTo($claims['sub'] ?? 'subject')
        ->issuedAt($claims['iat'] ?? $now)
        ->canOnlyBeUsedAfter($claims['nbf'] ?? $now)
        ->expiresAt($claims['exp'] ?? $now->modify('+10 minutes'));

    if (isset($claims['scopes']) && is_array($claims['scopes'])) {
        $builder = $builder->withClaim('scopes', $claims['scopes']);
    }
    foreach ($claims['custom'] ?? [] as $name => $value) {
        $builder = $builder->withClaim($name, $value);
    }

    return $builder->getToken($config->signer(), $config->signingKey())->toString();
}

function makeValidator(): JwksValidator
{
    $fetcher = new JwksFetcher(
        jwksUri: JWKS_URI,
        http: app(HttpFactory::class),
        cache: app(CacheFactory::class)->store(),
        cacheTtlSeconds: 3600,
        graceSeconds: 86400,
    );

    return new JwksValidator(
        jwks: $fetcher,
        issuer: ISSUER,
        audience: AUDIENCE,
        clockSkewSeconds: 30,
    );
}

test('validates a well-formed token signed with the published key', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'vault-prod',
        'scopes' => ['id.audit.write'],
    ]);

    $claims = makeValidator()->validate($token);

    expect($claims->sub)->toBe('vault-prod')
        ->and($claims->iss)->toBe(ISSUER)
        ->and($claims->audiences)->toContain(AUDIENCE)
        ->and($claims->scopes)->toBe(['id.audit.write'])
        ->and($claims->hasScope('id.audit.write'))->toBeTrue()
        ->and($claims->hasScope('id.usage.write'))->toBeFalse();
});

test('rejects a token signed with a different key', function (): void {
    [, , $publishedKid, $publishedRsa] = makeRsaKeypair('published-kid');
    [$attackerPrivate] = makeRsaKeypair('attacker-kid');

    fakeJwks([rsaPublicToJwk($publishedRsa, $publishedKid)]);

    // Mint a token signed by the attacker's private key but
    // labelled with the PUBLISHED kid — common forgery attempt.
    $token = mintToken($attackerPrivate, $publishedKid, ['sub' => 'attacker']);

    expect(fn () => makeValidator()->validate($token))
        ->toThrow(InvalidTokenException::class);
});

test('rejects a token whose kid is not in JWKS', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair('only-published');
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, 'unknown-kid', ['sub' => 'sub']);

    expect(fn () => makeValidator()->validate($token))
        ->toThrow(InvalidTokenException::class);
});

test('rejects a token with the wrong issuer', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'iss' => 'https://attacker.example.com',
        'sub' => 'sub',
    ]);

    expect(fn () => makeValidator()->validate($token))
        ->toThrow(InvalidTokenException::class);
});

test('rejects a token with the wrong audience', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'sub',
        'aud' => ['some-other-service.cbox.systems'],
    ]);

    expect(fn () => makeValidator()->validate($token))
        ->toThrow(InvalidTokenException::class);
});

test('accepts an array audience that includes the configured value', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'sub',
        'aud' => ['third-party.example', AUDIENCE, 'another.example'],
    ]);

    $claims = makeValidator()->validate($token);

    expect($claims->audiences)->toContain(AUDIENCE);
});

test('rejects an expired token', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'sub',
        'iat' => new \DateTimeImmutable('-2 hours'),
        'nbf' => new \DateTimeImmutable('-2 hours'),
        'exp' => new \DateTimeImmutable('-1 hour'),
    ]);

    expect(fn () => makeValidator()->validate($token))
        ->toThrow(InvalidTokenException::class);
});

test('rejects a token that is not yet valid (nbf in the future)', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'sub',
        'iat' => new \DateTimeImmutable('+5 minutes'),
        'nbf' => new \DateTimeImmutable('+5 minutes'),
        'exp' => new \DateTimeImmutable('+15 minutes'),
    ]);

    expect(fn () => makeValidator()->validate($token))
        ->toThrow(InvalidTokenException::class);
});

test('parses custom claims into the custom bag (e.g. platform_roles)', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => '42',
        'custom' => [
            'platform_roles' => ['staff', 'super_admin'],
            'oid' => 'org-slug',
        ],
    ]);

    $claims = makeValidator()->validate($token);

    expect($claims->customClaim('platform_roles'))->toBe(['staff', 'super_admin'])
        ->and($claims->customClaim('oid'))->toBe('org-slug')
        ->and($claims->userId())->toBe(42);
});

test('JWKS is cached so a second token validates without re-fetching', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $validator = makeValidator();

    $t1 = mintToken($privatePem, $kid, ['sub' => 'a']);
    $t2 = mintToken($privatePem, $kid, ['sub' => 'b']);

    $validator->validate($t1);
    $validator->validate($t2);

    Http::assertSentCount(1);
});

test('falls back to stale cached JWKS when id is unreachable but the cache is warm', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();

    // First request: id reachable, JWKS published normally.
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);
    $validator = makeValidator();
    $validator->validate(mintToken($privatePem, $kid, ['sub' => 'first']));

    // Now id goes down. New token still validates because the
    // grace path returns the previously-cached JWKS.
    Http::fake([JWKS_URI => Http::response('id is dead', 503)]);

    // Force the kid cache to be re-derived from the persistent
    // store — simulates a fresh pod that warms up while id is down.
    $freshValidator = makeValidator();

    expect(fn () => $freshValidator->validate(mintToken($privatePem, $kid, ['sub' => 'second'])))
        ->not->toThrow(InvalidTokenException::class);
});

test('rejects tokens that are not Plain JWTs (e.g. malformed strings)', function (): void {
    [, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    expect(fn () => makeValidator()->validate('not-a-jwt'))
        ->toThrow(InvalidTokenException::class);
});

test('rejects tokens that are missing the kid header', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    // Mint without kid by using lcobucci directly.
    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText($privatePem),
        InMemory::plainText('placeholder'),
    );
    $now = new \DateTimeImmutable;
    $token = $config->builder()
        ->issuedBy(ISSUER)
        ->permittedFor(AUDIENCE)
        ->relatedTo('x')
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+10 minutes'))
        ->getToken($config->signer(), $config->signingKey())
        ->toString();

    expect(fn () => makeValidator()->validate($token))
        ->toThrow(InvalidTokenException::class);
});
