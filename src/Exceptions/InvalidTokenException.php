<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth\Exceptions;

use RuntimeException;

/**
 * Thrown when a presented JWT fails validation — bad signature,
 * wrong issuer, wrong audience, expired, or malformed structure.
 *
 * Maps to HTTP 401 (`invalid_token`) at the middleware layer.
 */
final class InvalidTokenException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $reason,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
