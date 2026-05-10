<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth;

use Cbox\CboxIdJwksAuth\Exceptions\InsufficientScopeException;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\ServiceProvider;
use Throwable;

/**
 * Auto-discovered Laravel provider. Reads its config from
 * `services.cbox_id_jwks_auth` so the consumer keeps a single
 * `config/services.php` file.
 *
 * Required env vars:
 *   CBOX_ID_ISSUER       e.g. https://id.cbox.systems
 *   CBOX_ID_JWKS_URI     e.g. https://id.cbox.systems/.well-known/jwks.json
 *   CBOX_ID_AUDIENCE     this service's expected `aud` claim
 *
 * Optional:
 *   CBOX_ID_JWKS_CACHE_TTL          default 3600s
 *   CBOX_ID_JWKS_GRACE              default 86400s — fall back to cached JWKS during id outage
 *   CBOX_ID_JWKS_CLOCK_SKEW         default 30s
 *   CBOX_ID_JWKS_CACHE_STORE        cache store name (defaults to default)
 *
 * Consumer's `config/services.php`:
 *
 *   'cbox_id_jwks_auth' => [
 *       'issuer' => env('CBOX_ID_ISSUER'),
 *       'jwks_uri' => env('CBOX_ID_JWKS_URI'),
 *       'audience' => env('CBOX_ID_AUDIENCE'),
 *       'cache_ttl' => (int) env('CBOX_ID_JWKS_CACHE_TTL', 3600),
 *       'grace' => (int) env('CBOX_ID_JWKS_GRACE', 86400),
 *       'clock_skew' => (int) env('CBOX_ID_JWKS_CLOCK_SKEW', 30),
 *       'cache_store' => env('CBOX_ID_JWKS_CACHE_STORE'),
 *   ],
 */
class CboxIdJwksAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(JwksFetcher::class, function (Application $app): JwksFetcher {
            $config = $this->config();
            /** @var CacheRepository $cache */
            $cache = $this->resolveCache($app, $config['cache_store'] ?? null);

            return new JwksFetcher(
                jwksUri: (string) ($config['jwks_uri'] ?? ''),
                http: $app->make(HttpFactory::class),
                cache: $cache,
                cacheTtlSeconds: (int) ($config['cache_ttl'] ?? 3600),
                graceSeconds: (int) ($config['grace'] ?? 86400),
            );
        });

        $this->app->singleton(JwksValidator::class, function (Application $app): JwksValidator {
            $config = $this->config();

            return new JwksValidator(
                jwks: $app->make(JwksFetcher::class),
                issuer: (string) ($config['issuer'] ?? ''),
                audience: (string) ($config['audience'] ?? ''),
                clockSkewSeconds: (int) ($config['clock_skew'] ?? 30),
            );
        });
    }

    public function boot(): void
    {
        // Render InsufficientScopeException as 403 by default.
        // Apps with their own renderer can override.
        $this->app->resolving(ExceptionHandler::class, function (ExceptionHandler $handler): void {
            if (method_exists($handler, 'renderable')) {
                $handler->renderable(function (InsufficientScopeException $e): JsonResponse {
                    return new JsonResponse(
                        [
                            'error' => 'insufficient_scope',
                            'error_description' => $e->getMessage(),
                            'required_scope' => $e->requiredScope,
                        ],
                        403,
                        ['WWW-Authenticate' => 'Bearer error="insufficient_scope", scope="'.$e->requiredScope.'"'],
                    );
                });
            }
        });
    }

    /**
     * @return array<string, mixed>
     */
    private function config(): array
    {
        return (array) $this->app['config']->get('services.cbox_id_jwks_auth', []);
    }

    private function resolveCache(Application $app, mixed $store): CacheRepository
    {
        try {
            /** @var CacheFactory $factory */
            $factory = $app->make(CacheFactory::class);
            $name = is_string($store) && $store !== '' ? $store : null;
            /** @var CacheRepository $repo */
            $repo = $factory->store($name);

            return $repo;
        } catch (Throwable) {
            // Fallback to default array repo so misconfigured cache
            // doesn't crash construction in tests / CLI tools.
            /** @var CacheRepository $repo */
            $repo = $app->make(CacheFactory::class)->store('array');

            return $repo;
        }
    }
}
