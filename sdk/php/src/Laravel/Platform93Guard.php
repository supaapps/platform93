<?php
declare(strict_types=1);

namespace Supaapps\Platform93\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Supaapps\Platform93\Verifier;

final class Platform93Guard implements Guard
{
    private ?Platform93User $user = null;
    private bool $resolved = false;

    public function __construct(private readonly Verifier $verifier, private readonly Request $request) {}

    public function check(): bool { return $this->user() !== null; }
    public function guest(): bool { return !$this->check(); }

    public function user(): ?Authenticatable
    {
        if ($this->resolved) return $this->user;
        $this->resolved = true;
        $header = trim((string) $this->request->header('Authorization', ''));
        if (!str_starts_with(strtolower($header), 'bearer ')) return null;
        try {
            $claims = $this->verifier->verify(trim(substr($header, 7)));
            $this->user = new Platform93User($claims->values);
        } catch (\Throwable) {
            $this->user = null;
        }
        return $this->user;
    }

    public function id(): mixed { return $this->user()?->getAuthIdentifier(); }
    public function validate(array $credentials = []): bool { return false; }
    public function hasUser(): bool { return $this->user !== null; }
    public function setUser(Authenticatable $user): static
    {
        if (!$user instanceof Platform93User) throw new \InvalidArgumentException('Platform93Guard only accepts Platform93User.');
        $this->user = $user;
        $this->resolved = true;
        return $this;
    }
}
