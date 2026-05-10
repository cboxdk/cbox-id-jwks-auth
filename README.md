# cbox-id-jwks-auth (PHP)

JWKS-only validator + Laravel middleware for resource servers consuming Cbox
id-issued JWTs. Implements the validation half of
[`cbox-infra/docs/SERVICE_AUTH.md`](https://github.com/cboxdk/cbox-infra/blob/main/docs/SERVICE_AUTH.md).

Pair with [`cboxdk/cbox-id-tokens`](https://github.com/cboxdk/cbox-id-tokens)
when an app needs both to MINT id-issued tokens (caller side) AND
VALIDATE incoming ones (resource-server side).

## Why this exists

High-volume gateways (vault, OTel ingest, future managed services) can't
afford a roundtrip to id on every request. This validator caches id's JWKS
aggressively, validates JWTs locally, and tolerates id-down via a
configurable grace window — last good JWKS keeps serving up to 24h after a
fetch failure (default).

Revocation is **not** honoured by JWKS-only validation — the 10-minute
access-token TTL is the mitigation in v1; a distributed revocation feed is
on the roadmap.

## Install

```bash
composer require cboxdk/cbox-id-jwks-auth
```

Auto-discovered Laravel service provider.

## Configure

Add a `cbox_id_jwks_auth` block to `config/services.php`:

```php
'cbox_id_jwks_auth' => [
    'issuer' => env('CBOX_ID_ISSUER'),
    'jwks_uri' => env('CBOX_ID_JWKS_URI'),
    'audience' => env('CBOX_ID_AUDIENCE'),
    'cache_ttl' => (int) env('CBOX_ID_JWKS_CACHE_TTL', 3600),
    'grace' => (int) env('CBOX_ID_JWKS_GRACE', 86400),
    'clock_skew' => (int) env('CBOX_ID_JWKS_CLOCK_SKEW', 30),
    'cache_store' => env('CBOX_ID_JWKS_CACHE_STORE'),
],
```

`.env`:

```
CBOX_ID_ISSUER=https://id.cbox.systems
CBOX_ID_JWKS_URI=https://id.cbox.systems/.well-known/jwks.json
CBOX_ID_AUDIENCE=this-services-name.cbox.systems
```

## Use — middleware

```php
use Cbox\CboxIdJwksAuth\RequireOauthJwksValidation;

Route::middleware([RequireOauthJwksValidation::class])->group(function () {
    Route::post('/api/v1/audit', AuditController::class);
});

// Per-route required scope:
Route::middleware([RequireOauthJwksValidation::class.':id.audit.write'])
    ->post('/api/v1/audit/events', AuditEventsController::class);
```

On success, validated claims are stashed on the request:

```php
public function handle(Request $request)
{
    $claims = $request->attributes->get('cbox_jwks.claims'); // ValidatedClaims
    $sub = $request->attributes->get('cbox_jwks.sub');       // string
    $scopes = $request->attributes->get('cbox_jwks.scopes');  // list<string>
    $client = $request->attributes->get('cbox_jwks.client_id'); // ?string
}
```

Failure modes follow the OAuth 2.0 RFC:

- **401 invalid_token** — missing token, malformed, bad signature, expired,
  wrong issuer, wrong audience, unknown kid
- **403 insufficient_scope** — token valid but missing the required scope

## Use — Validator directly

If you need to validate tokens outside Laravel's middleware stack (e.g.
WebSocket handshake, queue jobs):

```php
use Cbox\CboxIdJwksAuth\JwksValidator;
use Cbox\CboxIdJwksAuth\Exceptions\InvalidTokenException;

try {
    $claims = $validator->validate($jwtString);
    if (! $claims->hasScope('id.audit.write')) {
        // 403
    }
    // ...
} catch (InvalidTokenException $e) {
    // 401, $e->reason = "expired" | "wrong_audience" | etc.
}
```

## License

MIT
