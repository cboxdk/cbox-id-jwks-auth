<?php

declare(strict_types=1);

namespace Cbox\CboxIdJwksAuth\Tests;

use Cbox\CboxIdJwksAuth\CboxIdJwksAuthServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            CboxIdJwksAuthServiceProvider::class,
        ];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
    }
}
