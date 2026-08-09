<?php
declare(strict_types=1);

namespace Supaapps\Platform93\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;

final class Platform93User implements Authenticatable
{
    /** @param array<string, mixed> $claims */
    public function __construct(private readonly array $claims) {}

    public function getAuthIdentifierName(): string { return 'sub'; }
    public function getAuthIdentifier(): mixed { return $this->claims['sub']; }
    public function getAuthPasswordName(): string { return 'password'; }
    public function getAuthPassword(): string { return ''; }
    public function getRememberToken(): ?string { return null; }
    public function setRememberToken($value): void {}
    public function getRememberTokenName(): string { return ''; }

    /** @return array<string, mixed> */
    public function claims(): array { return $this->claims; }

    public function can(string $permission): bool
    {
        foreach (preg_split('/\s+/', trim((string) ($this->claims['scope'] ?? ''))) ?: [] as $granted) {
            if ($granted === '*' || $granted === $permission || (str_ends_with($granted, '/*') && ($permission === substr($granted, 0, -2) || str_starts_with($permission, substr($granted, 0, -1))))) {
                return true;
            }
        }
        return false;
    }
}
