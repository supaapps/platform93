<?php
declare(strict_types=1);
namespace Supaapps\Platform93;

final class ResourceAuthorization {
    public static function uuid(mixed $value): bool {
        return is_string($value) && preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/D', $value) === 1;
    }

    public static function httpsUri(string $value): string {
        $parts = parse_url($value);
        if (preg_match('/[^\x21-\x7e]|["\\\\]/', $value) || $parts === false || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || str_contains($value, '#') || str_contains($value, '?')) throw new \InvalidArgumentException('Invalid HTTPS resource URI');
        return $value;
    }

    public static function capabilityScope(string $applicationId, string $capability): string {
        if (!self::uuid($applicationId) || strlen($capability) > 160 || in_array(explode(':', $capability)[0], ['roles', 'workspaces'], true)) throw new \InvalidArgumentException('Invalid resource capability');
        foreach (explode(':', $capability) as $part) {
            if (!preg_match('/\A[a-z0-9][a-z0-9._-]{0,63}\z/D', $part)) throw new \InvalidArgumentException('Invalid resource capability');
        }
        return '/applications/'.$applicationId.'/'.str_replace(':', '/', $capability);
    }

    /** @param list<string> $capabilities @return array{resource:string,authorization_servers:list<string>,scopes_supported:list<string>} */
    public static function metadata(string $resource, string $issuer, string $applicationId, array $capabilities): array {
        return ['resource' => self::httpsUri($resource), 'authorization_servers' => [self::httpsUri($issuer)], 'scopes_supported' => array_values(array_unique(array_map(static fn(string $key): string => self::capabilityScope($applicationId, $key), $capabilities)))];
    }

    public static function challenge(string $metadataUri, ?string $error = null, ?string $description = null): string {
        $quote = static function(string $value): string {
            if (preg_match('/[^\x20-\x7e]/', $value)) throw new \InvalidArgumentException('Invalid challenge value');
            return '"'.str_replace(['\\', '"'], ['\\\\', '\\"'], $value).'"';
        };
        if (!in_array($error, [null, 'invalid_token', 'insufficient_scope'], true)) throw new \InvalidArgumentException('Invalid challenge error');
        return 'Bearer resource_metadata='.$quote(self::httpsUri($metadataUri)).($error === null ? '' : ', error='.$quote($error)).($description === null ? '' : ', error_description='.$quote($description));
    }

    public static function validateClaims(array $claims, string $resource, string $applicationId, string $expectedScope): void {
        $reject = static function(): never { throw new \UnexpectedValueException('Platform93 resource token rejected'); };
        if (!(($claims['aud'] ?? null) === $resource || ($claims['aud'] ?? null) === [$resource])) $reject();
        foreach (['iat', 'nbf', 'exp'] as $key) if (!is_int($claims[$key] ?? null)) $reject();
        if ($claims['exp'] <= time() || $claims['nbf'] > time() || $claims['iat'] > time()) $reject();
        foreach (['sub', 'sid', 'connection_id'] as $key) if (!self::uuid($claims[$key] ?? null)) $reject();
        if (!is_string($claims['client_id'] ?? null) || !preg_match('/\A[\x21-\x7e]+\z/D', $claims['client_id'])) $reject();
        foreach (['act', 'workspace_id', 'workspace_ids', 'workspaces'] as $key) if (array_key_exists($key, $claims)) $reject();
        $roles = (array) $claims['roles'];
        if (($roles['application'] ?? null) !== [] || !is_object($roles['workspaces'] ?? null) || (array) $roles['workspaces'] !== []) $reject();
        $scopes = explode(' ', $claims['scope']);
        if (!in_array($expectedScope, $scopes, true)) $reject();
        $prefix = '/applications/'.$applicationId.'/';
        foreach ($scopes as $scope) {
            if (in_array($scope, ['openid', 'profile', 'email', 'offline_access'], true)) continue;
            if (!str_starts_with($scope, $prefix)) $reject();
            $key = str_replace('/', ':', substr($scope, strlen($prefix)));
            if (str_starts_with($key, 'workspaces:') || self::capabilityScope($applicationId, $key) !== $scope) $reject();
        }
    }
}
