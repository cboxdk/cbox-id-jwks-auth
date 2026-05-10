<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth;

use Cbox\CboxIdJwksAuth\Exceptions\InsufficientScopeException;
use Cbox\CboxIdJwksAuth\Exceptions\InvalidTokenException;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel HTTP middleware. Resource servers attach this to any
 * route that should accept Cbox id-issued JWTs.
 *
 * Optional scope requirement comes via the standard parameterised
 * middleware syntax:
 *
 *   Route::middleware([
 *       RequireOauthJwksValidation::class.':id.audit.write',
 *   ])->post(...);
 *
 * On success, the validated claims are stashed on the request:
 *
 *   $request->attributes->get('cbox_jwks.claims')   // ValidatedClaims
 *   $request->attributes->get('cbox_jwks.sub')      // string
 *   $request->attributes->get('cbox_jwks.scopes')   // list<string>
 *
 * Failure modes follow the OAuth 2.0 RFC:
 *   401 invalid_token       — missing/malformed/bad-signature/expired
 *   403 insufficient_scope  — token valid, scope missing
 */
class RequireOauthJwksValidation
{
    public function __construct(private readonly JwksValidator $validator) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, ?string $requiredScope = null): Response
    {
        $bearer = $this->extractBearer($request);
        if ($bearer === null) {
            return $this->unauthorized('missing_token', 'Missing Bearer token.');
        }

        try {
            $claims = $this->validator->validate($bearer);
        } catch (InvalidTokenException $e) {
            return $this->unauthorized($e->reason, $e->getMessage());
        }

        if ($requiredScope !== null && ! $claims->hasScope($requiredScope)) {
            throw new InsufficientScopeException($requiredScope);
        }

        $request->attributes->set('cbox_jwks.claims', $claims);
        $request->attributes->set('cbox_jwks.sub', $claims->sub);
        $request->attributes->set('cbox_jwks.scopes', $claims->scopes);
        $request->attributes->set('cbox_jwks.client_id', $claims->clientId);

        return $next($request);
    }

    private function extractBearer(Request $request): ?string
    {
        $header = (string) $request->header('Authorization', '');

        if ($header === '' || ! str_starts_with(strtolower($header), 'bearer ')) {
            return null;
        }

        return trim(substr($header, 7));
    }

    private function unauthorized(string $reason, string $description): JsonResponse
    {
        return new JsonResponse(
            [
                'error' => 'invalid_token',
                'error_description' => $description,
                'reason' => $reason,
            ],
            401,
            // RFC 6750 Section 3 — the WWW-Authenticate challenge so
            // SDK clients can render a meaningful retry-or-reauth UX.
            ['WWW-Authenticate' => "Bearer error=\"invalid_token\", error_description=\"{$description}\""],
        );
    }
}
