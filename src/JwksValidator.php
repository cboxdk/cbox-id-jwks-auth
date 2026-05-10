<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth;

use Carbon\CarbonImmutable;
use Cbox\CboxIdJwksAuth\Exceptions\InvalidTokenException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Throwable;

/**
 * High-volume token validator for resource servers consuming Cbox
 * id-issued JWTs. Validates against id's published JWKS WITHOUT
 * round-tripping to id per request — production gateways (vault,
 * OTel-gw) need this to scale.
 *
 * What's checked, in order:
 *
 *   1. Token parses as a Plain JWT with a `kid` header
 *   2. Signature verifies against the kid's public key from JWKS
 *   3. `iss` matches the configured issuer
 *   4. `aud` includes the configured audience (string or array form)
 *   5. `nbf` <= now (with clock-skew tolerance)
 *   6. `exp` > now (with clock-skew tolerance)
 *
 * Required-scope checks live at the middleware layer, not here —
 * the validator's job is "is this token genuine and current"; the
 * "and authorised for this endpoint" question is per-route.
 *
 * NOTE: revocation is not honoured by this validator. JWKS-only
 * validation cannot consult id's revocation store. The 10-min
 * access-token TTL is the mitigation in v1; a distributed
 * revocation feed is on the roadmap (see SERVICE_AUTH.md).
 */
final class JwksValidator
{
    private readonly Parser $parser;

    public function __construct(
        private readonly JwksFetcher $jwks,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly int $clockSkewSeconds = 30,
    ) {
        $this->parser = new Parser(new JoseEncoder);
    }

    /**
     * @throws InvalidTokenException
     */
    public function validate(string $tokenString): ValidatedClaims
    {
        $token = $this->parse($tokenString);

        $kid = $this->extractKid($token);
        $publicKeyPem = $this->jwks->publicKeyForKid($kid);

        $this->verifySignature($token, $publicKeyPem);
        $claims = $token->claims();

        $this->checkIssuer($claims->get('iss'));
        $this->checkAudience($claims->get('aud'));

        $now = CarbonImmutable::now();
        $this->checkNotBefore($claims->get('nbf'), $now);
        $this->checkExpiry($claims->get('exp'), $now);

        return $this->buildClaims($claims->all());
    }

    private function parse(string $tokenString): Plain
    {
        try {
            $token = $this->parser->parse($tokenString);
        } catch (Throwable $e) {
            throw new InvalidTokenException(
                "Token did not parse: {$e->getMessage()}",
                reason: 'malformed',
                previous: $e,
            );
        }

        if (! $token instanceof Plain) {
            throw new InvalidTokenException(
                'Token is not a Plain JWT.',
                reason: 'malformed',
            );
        }

        return $token;
    }

    private function extractKid(Plain $token): string
    {
        $kid = $token->headers()->get('kid');

        if (! is_string($kid) || $kid === '') {
            throw new InvalidTokenException(
                'Token header is missing the `kid` field.',
                reason: 'missing_kid',
            );
        }

        return $kid;
    }

    private function verifySignature(Plain $token, string $publicKeyPem): void
    {
        $config = Configuration::forAsymmetricSigner(
            new Sha256,
            // Signing key unused on this side (we only verify); pass
            // a placeholder so lcobucci's validator construction is
            // happy.
            InMemory::plainText('placeholder-not-used-for-verify'),
            InMemory::plainText($publicKeyPem),
        );

        $constraint = new SignedWith(
            new Sha256,
            InMemory::plainText($publicKeyPem),
        );

        $validator = new Validator;
        if (! $validator->validate($token, $constraint)) {
            throw new InvalidTokenException(
                'Token signature does not validate against JWKS.',
                reason: 'bad_signature',
            );
        }

        // Touch $config to keep the construction-time errors loud
        // for tests; PHPStan flags otherwise-unused locals.
        unset($config);
    }

    private function checkIssuer(mixed $iss): void
    {
        if (! is_string($iss) || $iss === '') {
            throw new InvalidTokenException('Token is missing iss claim.', reason: 'missing_iss');
        }
        if ($iss !== $this->issuer) {
            throw new InvalidTokenException(
                "Issuer `{$iss}` does not match expected `{$this->issuer}`.",
                reason: 'wrong_issuer',
            );
        }
    }

    private function checkAudience(mixed $aud): void
    {
        $audiences = is_array($aud) ? $aud : (is_string($aud) ? [$aud] : []);

        foreach ($audiences as $candidate) {
            if (is_string($candidate) && $candidate === $this->audience) {
                return;
            }
        }

        throw new InvalidTokenException(
            "Audience does not include `{$this->audience}`.",
            reason: 'wrong_audience',
        );
    }

    private function checkNotBefore(mixed $nbf, CarbonImmutable $now): void
    {
        if ($nbf === null) {
            return;
        }
        $instant = $this->coerceToCarbon($nbf, 'nbf');

        if ($instant->subSeconds($this->clockSkewSeconds)->greaterThan($now)) {
            throw new InvalidTokenException(
                'Token is not yet valid (nbf in the future).',
                reason: 'not_yet_valid',
            );
        }
    }

    private function checkExpiry(mixed $exp, CarbonImmutable $now): void
    {
        if ($exp === null) {
            throw new InvalidTokenException('Token is missing exp claim.', reason: 'missing_exp');
        }
        $instant = $this->coerceToCarbon($exp, 'exp');

        if ($instant->addSeconds($this->clockSkewSeconds)->lessThan($now)) {
            throw new InvalidTokenException(
                'Token has expired.',
                reason: 'expired',
            );
        }
    }

    private function coerceToCarbon(mixed $value, string $claim): CarbonImmutable
    {
        if ($value instanceof \DateTimeInterface) {
            return CarbonImmutable::instance($value);
        }
        if (is_int($value)) {
            return CarbonImmutable::createFromTimestamp($value);
        }
        if (is_string($value) && $value !== '') {
            try {
                return CarbonImmutable::parse($value);
            } catch (Throwable $e) {
                throw new InvalidTokenException(
                    "Token `{$claim}` claim is not a parseable timestamp.",
                    reason: "bad_{$claim}",
                    previous: $e,
                );
            }
        }
        throw new InvalidTokenException(
            "Token `{$claim}` claim has unexpected type.",
            reason: "bad_{$claim}",
        );
    }

    /**
     * @param  array<string, mixed>  $rawClaims
     */
    private function buildClaims(array $rawClaims): ValidatedClaims
    {
        $sub = is_string($rawClaims['sub'] ?? null) ? $rawClaims['sub'] : '';
        $iss = is_string($rawClaims['iss'] ?? null) ? $rawClaims['iss'] : '';
        $jti = is_string($rawClaims['jti'] ?? null) ? $rawClaims['jti'] : null;
        $clientId = is_string($rawClaims['client_id'] ?? null) ? $rawClaims['client_id'] : null;

        $audRaw = $rawClaims['aud'] ?? [];
        $audiences = is_array($audRaw)
            ? array_values(array_filter($audRaw, 'is_string'))
            : (is_string($audRaw) ? [$audRaw] : []);

        // League stores scopes as `scopes` (array). Standard OIDC
        // is `scope` (space-separated string). Accept both, prefer
        // the array form.
        $scopes = [];
        if (isset($rawClaims['scopes']) && is_array($rawClaims['scopes'])) {
            $scopes = array_values(array_filter($rawClaims['scopes'], 'is_string'));
        } elseif (isset($rawClaims['scope']) && is_string($rawClaims['scope'])) {
            $scopes = array_values(array_filter(explode(' ', $rawClaims['scope']), static fn ($s): bool => $s !== ''));
        }

        $known = ['sub', 'iss', 'aud', 'iat', 'exp', 'nbf', 'jti', 'client_id', 'scope', 'scopes'];
        $custom = [];
        foreach ($rawClaims as $key => $value) {
            if (! in_array($key, $known, true)) {
                $custom[$key] = $value;
            }
        }

        $exp = $this->coerceToCarbon($rawClaims['exp'] ?? null, 'exp');
        $iat = isset($rawClaims['iat'])
            ? $this->coerceToCarbon($rawClaims['iat'], 'iat')
            : CarbonImmutable::now();

        return new ValidatedClaims(
            sub: $sub,
            iss: $iss,
            audiences: $audiences,
            expiresAt: $exp,
            issuedAt: $iat,
            jti: $jti,
            clientId: $clientId,
            scopes: $scopes,
            custom: $custom,
        );
    }

    public static function makeChainedFormatter(): ChainedFormatter
    {
        return ChainedFormatter::default();
    }
}
