<?php
declare(strict_types=1);
namespace Supaapps\Platform93;
final readonly class Claims {
    public function __construct(public array $values) {}
    public function subject(): string { return (string) ($this->values['sub'] ?? ''); }
    public function applicationId(): string { return (string) ($this->values['application_id'] ?? ''); }
    public function isOrgVerified(): bool { return (bool) ($this->values['is_org_verified'] ?? false); }
    public function emailVerified(): bool { return (bool) ($this->values['email_verified'] ?? false); }
    public function locale(): string { return (string) ($this->values['locale'] ?? ''); }
    public function hasPermission(string $permission): bool {
        foreach (preg_split('/\s+/', trim((string) ($this->values['scope'] ?? ''))) ?: [] as $granted) {
            if ($granted === '*' || $granted === $permission || (str_ends_with($granted, '/*') && ($permission === substr($granted, 0, -2) || str_starts_with($permission, substr($granted, 0, -1))))) return true;
        }
        return false;
    }
}
