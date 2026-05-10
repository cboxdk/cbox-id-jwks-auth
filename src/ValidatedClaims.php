<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth;

use Carbon\CarbonImmutable;

/**
 * Parsed + validated JWT claims. Returned by JwksValidator::validate
 * after signature, issuer, audience, and expiry have been confirmed.
 *
 * Standard OIDC fields are typed; the `custom` array carries the
 * remaining claims (e.g. `platform_roles`, `roles`, `seats`) so
 * callers can read them without knowing every one in advance.
 */
final readonly class ValidatedClaims
{
    /**
     * @param  list<string>  $audiences
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $custom
     */
    public function __construct(
        public string $sub,
        public string $iss,
        public array $audiences,
        public CarbonImmutable $expiresAt,
        public CarbonImmutable $issuedAt,
        public ?string $jti,
        public ?string $clientId,
        public array $scopes,
        public array $custom,
    ) {}

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    public function hasAnyScope(string ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($this->hasScope($scope)) {
                return true;
            }
        }

        return false;
    }

    public function hasAllScopes(string ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if (! $this->hasScope($scope)) {
                return false;
            }
        }

        return true;
    }

    public function customClaim(string $name): mixed
    {
        return $this->custom[$name] ?? null;
    }

    /**
     * Convenience accessor for the `sub` claim parsed as an integer.
     * Service-tier client_credentials tokens carry a string subject
     * (the client_id); user-bound tokens carry a numeric user id.
     * Returns null when the subject isn't a digit string.
     */
    public function userId(): ?int
    {
        return ctype_digit($this->sub) ? (int) $this->sub : null;
    }
}
