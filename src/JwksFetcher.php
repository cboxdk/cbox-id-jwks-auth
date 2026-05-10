<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth;

use Cbox\CboxIdJwksAuth\Exceptions\InvalidTokenException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Client\Factory as HttpFactory;
use Throwable;

/**
 * Fetches and caches the JWKS document from id's
 * /.well-known/jwks.json. Resolves a public key for a given `kid`
 * with three strategies in order:
 *
 *   1. In-memory cache lookup by kid (sub-microsecond)
 *   2. Persistent cache lookup of the full JWKS doc by URL
 *   3. Fresh HTTP fetch, replacing both caches
 *
 * On HTTP fetch failure, falls back to the most recent cached doc
 * if it's still inside the grace window — id-outage tolerance for
 * resource servers that can't talk to id every request.
 */
final class JwksFetcher
{
    private const CACHE_KEY_PREFIX = 'cbox:jwks:';

    /**
     * In-process key cache by kid. Reset on every JWKS refresh —
     * if the JWKS doc changed (key rotation) we re-derive PEMs from
     * scratch.
     *
     * @var array<string, string>
     */
    private array $kidToPem = [];

    /** ISO-8601 timestamp of the most recent successful fetch. */
    private ?string $lastFetchAt = null;

    public function __construct(
        private readonly string $jwksUri,
        private readonly HttpFactory $http,
        private readonly CacheRepository $cache,
        private readonly int $cacheTtlSeconds = 3600,
        private readonly int $graceSeconds = 86400,
    ) {}

    /**
     * Returns the PEM-encoded public key for the given `kid`. Throws
     * InvalidTokenException when no matching key can be resolved
     * (forces 401 — we won't validate against an unknown signer).
     *
     * @throws InvalidTokenException
     */
    public function publicKeyForKid(string $kid): string
    {
        if (isset($this->kidToPem[$kid])) {
            return $this->kidToPem[$kid];
        }

        $jwks = $this->loadJwks(allowStaleOnError: true);

        if (! isset($jwks[$kid])) {
            // Unknown kid — refresh once before giving up. id may
            // have rotated keys since our cache was warm.
            $jwks = $this->loadJwks(forceRefresh: true, allowStaleOnError: false);
        }

        if (! isset($jwks[$kid])) {
            throw new InvalidTokenException(
                "No JWKS key matches kid={$kid}.",
                reason: 'unknown_kid',
            );
        }

        return $this->kidToPem[$kid] = $jwks[$kid];
    }

    /**
     * @return array<string, string> kid → PEM
     *
     * @throws InvalidTokenException when fetch fails AND no usable cached doc
     */
    private function loadJwks(bool $forceRefresh = false, bool $allowStaleOnError = true): array
    {
        $cacheKey = self::CACHE_KEY_PREFIX.hash('sha256', $this->jwksUri);

        if (! $forceRefresh) {
            /** @var array{fetched_at: string, keys: array<string, string>}|null $cached */
            $cached = $this->cache->get($cacheKey);
            if (is_array($cached) && isset($cached['keys']) && is_array($cached['keys'])) {
                /** @var array<string, string> $keys */
                $keys = $cached['keys'];
                $this->kidToPem = $keys;
                $this->lastFetchAt = (string) ($cached['fetched_at'] ?? '');

                return $keys;
            }
        }

        try {
            $response = $this->http->acceptJson()->timeout(5)->get($this->jwksUri);
            if (! $response->successful()) {
                throw new \RuntimeException("HTTP {$response->status()}: ".substr((string) $response->body(), 0, 200));
            }
            /** @var array{keys?: array<int, array<string, mixed>>}|null $body */
            $body = $response->json();
            if (! is_array($body) || ! isset($body['keys']) || ! is_array($body['keys'])) {
                throw new \RuntimeException('JWKS response missing `keys` array.');
            }
            $keys = $this->jwksToPemMap($body['keys']);

            $this->kidToPem = $keys;
            $this->lastFetchAt = now()->toIso8601String();
            $this->cache->put(
                $cacheKey,
                ['fetched_at' => $this->lastFetchAt, 'keys' => $keys],
                $this->cacheTtlSeconds,
            );

            return $keys;
        } catch (Throwable $e) {
            // Fetch failed. Try the persistent cache as fallback even
            // if it's past TTL — caller-defined grace window keeps
            // us serving valid tokens during id outage.
            if ($allowStaleOnError) {
                /** @var array{fetched_at: string, keys: array<string, string>}|null $stale */
                $stale = $this->cache->get($cacheKey.':stale');
                if (is_array($stale) && isset($stale['keys']) && is_array($stale['keys'])) {
                    $fetchedAt = (string) ($stale['fetched_at'] ?? '');
                    if ($fetchedAt !== '' && now()->diffInSeconds($fetchedAt) <= $this->graceSeconds) {
                        /** @var array<string, string> $keys */
                        $keys = $stale['keys'];
                        $this->kidToPem = $keys;
                        $this->lastFetchAt = $fetchedAt;

                        return $keys;
                    }
                }
            }

            throw new InvalidTokenException(
                "Cannot fetch JWKS at {$this->jwksUri}: {$e->getMessage()}",
                reason: 'jwks_unavailable',
                previous: $e,
            );
        } finally {
            // Always update the long-TTL stale copy on a successful
            // path. Done in finally so the call above doesn't cancel
            // our durability guarantee on a partial failure later.
            if ($this->lastFetchAt !== null) {
                $this->cache->put(
                    $cacheKey.':stale',
                    ['fetched_at' => $this->lastFetchAt, 'keys' => $this->kidToPem],
                    $this->cacheTtlSeconds + $this->graceSeconds,
                );
            }
        }
    }

    /**
     * @param  array<int, array<string, mixed>>  $keys
     * @return array<string, string> kid → PEM
     *
     * @throws \RuntimeException
     */
    private function jwksToPemMap(array $keys): array
    {
        $out = [];
        foreach ($keys as $key) {
            $kid = is_string($key['kid'] ?? null) ? $key['kid'] : null;
            $kty = is_string($key['kty'] ?? null) ? $key['kty'] : null;
            $n = is_string($key['n'] ?? null) ? $key['n'] : null;
            $e = is_string($key['e'] ?? null) ? $key['e'] : null;

            if ($kid === null || $kty !== 'RSA' || $n === null || $e === null) {
                continue;
            }

            $out[$kid] = $this->rsaJwkToPem($n, $e);
        }

        if ($out === []) {
            throw new \RuntimeException('JWKS response contained no usable RSA keys.');
        }

        return $out;
    }

    /**
     * Convert a base64url-encoded RSA modulus + exponent into a PEM-
     * encoded SubjectPublicKeyInfo (SPKI) suitable for openssl /
     * lcobucci/jwt verification.
     */
    private function rsaJwkToPem(string $nBase64Url, string $eBase64Url): string
    {
        $n = self::base64UrlDecode($nBase64Url);
        $e = self::base64UrlDecode($eBase64Url);

        $modulus = self::asn1Integer($n);
        $exponent = self::asn1Integer($e);
        $rsaPublicKey = self::asn1Sequence($modulus.$exponent);

        // RSA OID: 1.2.840.113549.1.1.1
        $algorithmIdentifier = self::asn1Sequence(
            "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
            ."\x05\x00",
        );

        $bitString = self::asn1BitString($rsaPublicKey);
        $spki = self::asn1Sequence($algorithmIdentifier.$bitString);

        return "-----BEGIN PUBLIC KEY-----\n".
            chunk_split(base64_encode($spki), 64, "\n").
            "-----END PUBLIC KEY-----\n";
    }

    private static function base64UrlDecode(string $value): string
    {
        $remainder = strlen($value) % 4;
        if ($remainder !== 0) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }

    private static function asn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    private static function asn1Integer(string $value): string
    {
        if ($value !== '' && (ord($value[0]) & 0x80) !== 0) {
            $value = "\x00".$value;
        }

        return "\x02".self::asn1Length(strlen($value)).$value;
    }

    private static function asn1BitString(string $value): string
    {
        return "\x03".self::asn1Length(strlen($value) + 1)."\x00".$value;
    }

    private static function asn1Sequence(string $value): string
    {
        return "\x30".self::asn1Length(strlen($value)).$value;
    }
}
