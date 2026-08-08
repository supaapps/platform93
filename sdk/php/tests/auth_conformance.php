<?php
declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Supaapps\Platform93\Verifier;

final class TestCacheItem implements CacheItemInterface {
    public function __construct(private string $key, private mixed $value = null, private bool $hit = false) {}
    public function getKey(): string { return $this->key; }
    public function get(): mixed { return $this->value; }
    public function isHit(): bool { return $this->hit; }
    public function set(mixed $value): static { $this->value = $value; $this->hit = true; return $this; }
    public function expiresAt(?DateTimeInterface $expiration): static { return $this; }
    public function expiresAfter(DateInterval|int|null $time): static { return $this; }
}

final class TestCachePool implements CacheItemPoolInterface {
    /** @var array<string, TestCacheItem> */
    private array $items = [];
    public function getItem(string $key): CacheItemInterface { return $this->items[$key] ?? new TestCacheItem($key); }
    public function getItems(array $keys = []): iterable { foreach ($keys as $key) yield $key => $this->getItem($key); }
    public function hasItem(string $key): bool { return isset($this->items[$key]); }
    public function clear(): bool { $this->items = []; return true; }
    public function deleteItem(string $key): bool { unset($this->items[$key]); return true; }
    public function deleteItems(array $keys): bool { foreach ($keys as $key) unset($this->items[$key]); return true; }
    public function save(CacheItemInterface $item): bool { $this->items[$item->getKey()] = $item; return true; }
    public function saveDeferred(CacheItemInterface $item): bool { return $this->save($item); }
    public function commit(): bool { return true; }
}

$fixture = json_decode(file_get_contents(__DIR__.'/../../../conformance/jwt.json'), true, 32, JSON_THROW_ON_ERROR);
$primary = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$wrong = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
if ($primary === false || $wrong === false) throw new RuntimeException('RSA fixture generation failed');
openssl_pkey_export($primary, $primaryPEM);
openssl_pkey_export($wrong, $wrongPEM);
$details = openssl_pkey_get_details($primary);
$b64 = static fn(string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
$jwks = ['keys' => [[
    'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => 'primary',
    'n' => $b64($details['rsa']['n']), 'e' => $b64($details['rsa']['e']),
]]];
$issuer = 'https://issuer.platform93.test';
$verifier = new Verifier($issuer.'/', $fixture['audience'], $fixture['application_id'], new TestCachePool(), static fn(): array => $jwks);

foreach ($fixture['cases'] as $case) {
    $now = time();
    $claims = ['iss' => $issuer, 'sub' => 'user-1', 'aud' => [$fixture['audience']], 'exp' => $now + 300, 'iat' => $now, 'nbf' => $now - 1,
        'application_id' => $fixture['application_id'], 'token_kind' => 'access', 'actor_type' => 'user', 'scope' => '/applications/app/profile/read'];
    $kid = 'primary';
    $key = $primaryPEM;
    switch ($case['mutation']) {
        case 'machine': $claims['token_kind'] = 'machine'; $claims['actor_type'] = 'client'; break;
        case 'delegated': $claims['act'] = ['sub' => 'operator-1', 'type' => 'operator']; break;
        case 'wrong_issuer': $claims['iss'] = 'https://wrong.example'; break;
        case 'wrong_audience': $claims['aud'] = ['wrong-api']; break;
        case 'wrong_application': $claims['application_id'] = '01900000-0000-7000-8000-000000000000'; break;
        case 'expired': $claims['exp'] = $now - 60; break;
        case 'future_nbf': $claims['nbf'] = $now + 300; break;
        case 'future_iat': $claims['iat'] = $now + 300; break;
        case 'missing_sub': unset($claims['sub']); break;
        case 'missing_application': unset($claims['application_id']); break;
        case 'missing_token_kind': unset($claims['token_kind']); break;
        case 'missing_actor_type': unset($claims['actor_type']); break;
        case 'operator_actor': $claims['actor_type'] = 'operator'; break;
        case 'missing_kid': $kid = null; break;
        case 'unknown_kid': $kid = 'unknown'; break;
        case 'wrong_signature': $key = $wrongPEM; break;
        case 'delegated_wrong_actor_type': $claims['act'] = ['sub' => 'operator-1', 'type' => 'user']; break;
    }
    $token = JWT::encode($claims, $key, 'RS256', $kid, ['typ' => 'JWT']);
    if ($case['mutation'] === 'wrong_algorithm') {
        $parts = explode('.', $token);
        $parts[0] = $b64(json_encode(['alg' => 'HS256', 'typ' => 'JWT', 'kid' => 'primary'], JSON_THROW_ON_ERROR));
        $token = implode('.', $parts);
    }
    $accepted = true;
    try { $verifier->verify($token); } catch (Throwable) { $accepted = false; }
    if ($accepted !== $case['accept']) throw new RuntimeException('JWT conformance failed: '.$case['name']);
}
