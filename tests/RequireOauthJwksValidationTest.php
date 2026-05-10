<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth\Tests;

use Cbox\CboxIdJwksAuth\Exceptions\InsufficientScopeException;
use Cbox\CboxIdJwksAuth\RequireOauthJwksValidation;
use Cbox\CboxIdJwksAuth\ValidatedClaims;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

beforeEach(function (): void {
    Cache::flush();
});

/**
 * Reuses the helpers defined in JwksValidatorTest (Pest auto-loads
 * test files so the keypair / JWKS fixture functions are available).
 */
function middleware(): RequireOauthJwksValidation
{
    return new RequireOauthJwksValidation(makeValidator());
}

function requestWithBearer(string $bearer): Request
{
    return Request::create('/x', 'GET', server: [
        'HTTP_AUTHORIZATION' => "Bearer {$bearer}",
    ]);
}

test('returns 401 invalid_token when the Authorization header is missing', function (): void {
    $request = Request::create('/x', 'GET');

    $response = middleware()->handle($request, fn () => response('ok'));

    expect($response->getStatusCode())->toBe(401);
    $body = json_decode((string) $response->getContent(), true);
    expect($body['error'])->toBe('invalid_token')
        ->and($body['reason'])->toBe('missing_token');
    expect($response->headers->get('WWW-Authenticate'))->toContain('Bearer error="invalid_token"');
});

test('returns 401 invalid_token when the Bearer is malformed', function (): void {
    [, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $response = middleware()->handle(
        requestWithBearer('not-a-jwt'),
        fn () => response('ok'),
    );

    expect($response->getStatusCode())->toBe(401);
});

test('lets the request through when token is valid and stashes claims on the request', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'vault-prod',
        'scopes' => ['id.audit.write'],
    ]);

    $captured = null;
    $response = middleware()->handle(
        requestWithBearer($token),
        function (Request $req) use (&$captured) {
            $captured = $req;

            return response('ok');
        },
    );

    expect($response->getStatusCode())->toBe(200);

    /** @var Request $captured */
    expect($captured->attributes->get('cbox_jwks.sub'))->toBe('vault-prod')
        ->and($captured->attributes->get('cbox_jwks.scopes'))->toBe(['id.audit.write'])
        ->and($captured->attributes->get('cbox_jwks.claims'))->toBeInstanceOf(ValidatedClaims::class);
});

test('throws InsufficientScopeException when the required scope is absent', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'vault-prod',
        'scopes' => ['id.audit.write'],
    ]);

    expect(fn () => middleware()->handle(
        requestWithBearer($token),
        fn () => response('ok'),
        'id.usage.write', // required-scope param
    ))->toThrow(InsufficientScopeException::class);
});

test('passes through when the required scope IS present', function (): void {
    [$privatePem, , $kid, $rsa] = makeRsaKeypair();
    fakeJwks([rsaPublicToJwk($rsa, $kid)]);

    $token = mintToken($privatePem, $kid, [
        'sub' => 'vault-prod',
        'scopes' => ['id.audit.write', 'id.usage.write'],
    ]);

    $response = middleware()->handle(
        requestWithBearer($token),
        fn () => response('ok'),
        'id.usage.write',
    );

    expect($response->getStatusCode())->toBe(200);
});
