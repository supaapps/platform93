<?php
declare(strict_types=1);
namespace Supaapps\Platform93;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Psr\Cache\CacheItemPoolInterface;
final class Verifier {
    private string $issuer;
    private ?\Closure $jwksLoader;
    public function __construct(string $issuer, private string $audience, private string $applicationId, private CacheItemPoolInterface $cache, ?callable $jwksLoader = null) {
        $this->issuer = rtrim($issuer, '/');
        $this->jwksLoader = $jwksLoader === null ? null : \Closure::fromCallable($jwksLoader);
    }
    public function verify(string $token): Claims {
        $parts = explode('.', $token);
        if (count($parts) !== 3) throw new \UnexpectedValueException('Platform93 token is malformed');
        $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true, 8, JSON_THROW_ON_ERROR);
        if (($header['alg'] ?? null) !== 'RS256' || ($header['typ'] ?? null) !== 'JWT' || !is_string($header['kid'] ?? null) || $header['kid'] === '') throw new \UnexpectedValueException('Platform93 token algorithm rejected');
        $item = $this->cache->getItem('platform93_jwks_'.hash('sha256', $this->issuer));
        if (!$item->isHit()) {
            $json = $this->jwksLoader ? ($this->jwksLoader)($this->issuer.'/jwks.json') : @file_get_contents($this->issuer.'/jwks.json');
            if ($json === false) throw new \RuntimeException('Platform93 JWKS is unavailable');
            $jwks = is_array($json) ? $json : json_decode($json, true, 32, JSON_THROW_ON_ERROR);
            $item->set($jwks)->expiresAfter(300); $this->cache->save($item);
        } else $jwks = $item->get();
        $claims = (array) JWT::decode($token, JWK::parseKeySet($jwks, 'RS256'));
        $audiences = (array) ($claims['aud'] ?? []);
        foreach (['iss','sub','aud','exp','iat','nbf','application_id','token_kind','actor_type','scope','roles'] as $required) {
            if (!array_key_exists($required, $claims)) throw new \UnexpectedValueException('Platform93 token claim missing');
        }
        $validActor = ($claims['token_kind'] ?? null) === 'access' && ($claims['actor_type'] ?? null) === 'user'
            || ($claims['token_kind'] ?? null) === 'machine' && ($claims['actor_type'] ?? null) === 'client';
        if (!is_string($claims['sub']) || $claims['sub'] === '' || ($claims['iss'] ?? null) !== $this->issuer || !in_array($this->audience, $audiences, true) || ($claims['application_id'] ?? null) !== $this->applicationId || !$validActor || !is_string($claims['scope']) || !is_int($claims['iat']) || $claims['iat'] > time() + JWT::$leeway) throw new \UnexpectedValueException('Platform93 token context rejected');
        $actor = (array) ($claims['act'] ?? []);
        if ($actor !== [] && ($claims['token_kind'] !== 'access' || !is_string($actor['sub'] ?? null) || $actor['sub'] === '' || ($actor['type'] ?? null) !== 'control_user')) throw new \UnexpectedValueException('Platform93 delegated token actor rejected');
        if (!Permission::validateAuthorizationClaims($claims['scope'], $claims['roles'], $this->applicationId, $actor !== [])) throw new \UnexpectedValueException('Platform93 token authorization claims rejected');
        return new Claims($claims);
    }
}
