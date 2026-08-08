<?php
declare(strict_types=1);

namespace Supaapps\Platform93\Laravel;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Supaapps\Platform93\Verifier;

final class Platform93ServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Auth::extend('platform93', function ($app, string $name, array $config): Platform93Guard {
            foreach (['issuer', 'audience', 'application_id'] as $required) {
                if (!isset($config[$required]) || !is_string($config[$required]) || $config[$required] === '') {
                    throw new \InvalidArgumentException("Platform93 guard '{$name}' requires '{$required}'.");
                }
            }
            $verifier = new Verifier(
                $config['issuer'],
                $config['audience'],
                $config['application_id'],
                $app['cache.store'],
            );
            return new Platform93Guard($verifier, $app['request']);
        });
    }
}
