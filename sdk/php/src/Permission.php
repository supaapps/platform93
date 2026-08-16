<?php
declare(strict_types=1);
namespace Supaapps\Platform93;

final class Permission {
    private const SEGMENT = '/\A[a-z0-9][a-z0-9._-]{0,63}\z/D';
    private const ROLE_KEY = '/\A[a-z][a-z0-9_-]{0,62}\z/D';
    private const WORKSPACE_KEY = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/D';

    public static function validateAuthorizationClaims(string $scope, mixed $roles, string $applicationId, bool $delegated): bool {
        if (!self::validateScope($scope, $applicationId) || (!is_object($roles) && !is_array($roles))) return false;
        $value = (array) $roles;
        if (array_diff(array_keys($value), ['application', 'workspaces']) !== [] || !array_key_exists('application', $value) || !array_key_exists('workspaces', $value)) return false;
        if (!is_array($value['application']) || (!is_object($value['workspaces']) && !is_array($value['workspaces'])) || !self::uniqueRoles($value['application'])) return false;
        $workspaces = (array) $value['workspaces'];
        foreach ($workspaces as $workspaceId => $workspaceRoles) {
            if (!preg_match(self::WORKSPACE_KEY, (string) $workspaceId) || !is_array($workspaceRoles) || !self::uniqueRoles($workspaceRoles)) return false;
        }
        return !$delegated || ($value['application'] === [] && $workspaces === []);
    }

    public static function matches(string $granted, string $wanted): bool {
        if (!self::validAbsolute($granted) || !self::validAbsolute($wanted)) return false;
        if ($granted === $wanted) return true;
        if (!str_ends_with($granted, '/*')) return false;
        $base = substr($granted, 0, -2);
        return $wanted === $base || str_starts_with($wanted, $base.'/');
    }

    private static function validateScope(string $scope, string $applicationId): bool {
        if ($scope === '') return true;
        if ($scope !== trim($scope) || str_contains($scope, "\t") || str_contains($scope, "\r") || str_contains($scope, "\n") || str_contains($scope, '  ')) return false;
        $values = explode(' ', $scope);
        if (count($values) !== count(array_unique($values))) return false;
        $prefix = '/applications/'.$applicationId.'/';
        foreach ($values as $value) {
            if (in_array($value, ['openid', 'profile', 'email', 'offline_access'], true)) continue;
            if (!str_starts_with($value, $prefix) || !self::validAbsolute($value)) return false;
        }
        return true;
    }

    private static function validAbsolute(string $value): bool {
        if (!str_starts_with($value, '/') || preg_match('/[ :\\\\%\t\r\n]/', $value)) return false;
        $segments = explode('/', substr($value, 1));
        if (count($segments) < 3) return false;
        foreach ($segments as $index => $segment) {
            if ($segment === '*') {
                if ($index !== array_key_last($segments)) return false;
                continue;
            }
            if (!preg_match(self::SEGMENT, $segment)) return false;
        }
        return true;
    }

    private static function uniqueRoles(array $values): bool {
        foreach ($values as $value) if (!is_string($value) || !preg_match(self::ROLE_KEY, $value)) return false;
        return count($values) === count(array_unique($values));
    }
}
