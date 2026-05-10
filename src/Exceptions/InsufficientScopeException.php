<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth\Exceptions;

use RuntimeException;

/**
 * Thrown when a token validates correctly but lacks a scope the
 * endpoint requires.
 *
 * Maps to HTTP 403 (`insufficient_scope`) at the middleware layer —
 * matches the OAuth 2.0 RFC: 401 = "no token / bad token", 403 =
 * "token but not enough authority".
 */
final class InsufficientScopeException extends RuntimeException
{
    public function __construct(
        public readonly string $requiredScope,
    ) {
        parent::__construct("Required scope `{$requiredScope}` is not present in the token.");
    }
}
