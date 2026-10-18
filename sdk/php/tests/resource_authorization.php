<?php
declare(strict_types=1);

require __DIR__.'/auth_conformance.php';

use Firebase\JWT\JWT;
use Supaapps\Platform93\MachineClient;
use Supaapps\Platform93\ResourceAuthorization;
use Supaapps\Platform93\Verifier;

function expectResource(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}
function rejectsResource(callable $call): void {
    try { $call(); } catch (Throwable) { return; }
    throw new RuntimeException('Expected resource authorization failure');
}

$app = $fixture['application_id'];
$id = '01900000-0000-7000-8000-000000000094';
$resource = 'https://resource.example/api';
$scope = ResourceAuthorization::capabilityScope($app, 'documents:read');
$resourceFixture = json_decode(file_get_contents(__DIR__.'/../../../conformance/resource-jwt.json'), false, 64, JSON_THROW_ON_ERROR);
$verifier = new Verifier($issuer, $resource, $app, new TestCachePool(), static fn(): array => $jwks);
$checks = 0;
$exchanges = 0;
$decision = ['allowed' => true, 'reason' => 'allowed', 'user_id' => $id, 'connection_id' => $id];
$lastRequest = null;
$offline = false;
$machine = new MachineClient($issuer, $app, 'backend', 'test', [], function(string $method, string $url, array $headers, ?string $body) use (&$checks, &$exchanges, &$lastRequest, &$decision, &$offline, $issuer, $app): array {
    if ($url === $issuer.'/oidc/token') {
        $exchanges++;
        expectResource(in_array('Authorization: Basic '.base64_encode('backend:test'), $headers, true), 'Missing machine credentials');
        expectResource($body === 'grant_type=client_credentials', 'Incorrect client credentials exchange');
        return ['access_token' => 'machine', 'expires_in' => 300];
    }
    expectResource($url === $issuer.'/v1/applications/'.$app.'/service/resource-access/check' && $method === 'POST', 'Incorrect live-check route');
    expectResource(in_array('Authorization: Bearer machine', $headers, true), 'Missing machine bearer');
    $checks++;
    $lastRequest = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    if ($offline) throw new RuntimeException('HTTP 503 unavailable');
    return $decision;
});
$makeToken = function(array $changes = [], array $omit = []) use ($issuer, $resource, $app, $id, $scope, $primaryPEM, $resourceFixture): string {
    $now = time();
    $claims = array_replace(['iss' => $issuer, 'exp' => $now + 300, 'iat' => $now, 'nbf' => $now - 1], (array) $resourceFixture->claims, $changes);
    foreach ($omit as $key) unset($claims[$key]);
    return JWT::encode($claims, $primaryPEM, 'RS256', 'primary', ['typ' => 'JWT']);
};
$authorize = static fn(string $token, ?string $workspaceId = null) => $verifier->authorizeResource($token, $resource, 'documents:read', $machine, $workspaceId);
foreach ($resourceFixture->cases as $case) {
    $before = $checks;
    $accepted = true;
    try { $authorize($makeToken((array) ($case->changes ?? []), $case->omit ?? [])); } catch (Throwable) { $accepted = false; }
    expectResource($accepted === $case->accept, 'Shared resource JWT conformance failed: '.$case->name);
    expectResource($checks - $before === ($case->accept ? 1 : 0), 'Shared resource JWT live-check parity failed: '.$case->name);
}
$checks = 0;
$token = $makeToken();
expectResource($authorize($token)->values['connection_id'] === $id, 'Valid resource token rejected');
$authorize($token);
expectResource($checks === 2 && $exchanges === 1, 'Resource decision cached or machine token not cached');
expectResource($lastRequest === ['token' => $token, 'resource' => $resource, 'capability' => 'documents:read'], 'Incorrect live request');
rejectsResource(static fn() => $verifier->verify($token));
$decision['workspace_id'] = $id;
$authorize($token, $id);
expectResource($lastRequest['workspace_id'] === $id, 'Workspace not passed explicitly');
$decision = ['allowed' => false, 'reason' => 'revoked'];
rejectsResource(static fn() => $authorize($token));
$before = $checks;
foreach ([
    ['application_id' => $id], ['iss' => $resource], ['aud' => $resource.'/other'], ['aud' => [$resource, $issuer]], ['aud' => [$resource, $resource]],
    ['actor_type' => 'client'], ['token_kind' => 'access'], ['sid' => 'bad'], ['connection_id' => 'bad'], ['client_id' => ''],
    ['exp' => 1], ['iat' => time() + 1000], ['nbf' => time() + 1000], ['exp' => (string) (time() + 300)],
    ['roles' => ['application' => ['member'], 'workspaces' => new stdClass()]], ['roles' => ['application' => [], 'workspaces' => [$id => []]]],
    ['workspace_ids' => [$id]], ['workspace_id' => $id], ['act' => null], ['scope' => ''], ['scope' => $scope.' '.$scope],
    ['scope' => $scope."\t".$scope], ['scope' => '/applications/'.$app.'/*'], ['scope' => $scope.' admin'], ['scope' => 'openid offline_access'],
    ['scope' => $scope.' /applications/'.$app.'/roles/member'],
    ['scope' => '/applications/'.$id.'/documents/read'], ['scope' => $scope.' /applications/'.$app.'/workspaces/'.$id.'/read'],
] as $changes) rejectsResource(static fn() => $authorize($makeToken($changes)));
foreach (['sub', 'sid', 'client_id', 'connection_id', 'scope', 'roles', 'exp', 'iat', 'nbf'] as $claim) rejectsResource(static fn() => $authorize($makeToken([], [$claim])));
expectResource($checks === $before, 'Live check happened before local rejection');
rejectsResource(static fn() => $authorize($makeToken(['padding' => str_repeat('a', 16 * 1024)])));
expectResource($checks === $before, 'Oversized token reached live check');
foreach ([[], ['allowed' => 'true', 'reason' => 'ok'], ['allowed' => true], ['allowed' => true, 'reason' => null],
    ['allowed' => true, 'reason' => 'ok', 'user_id' => $app], ['allowed' => true, 'reason' => 'ok', 'connection_id' => null],
    ['allowed' => true, 'reason' => 'ok', 'workspace_id' => $id]] as $response) {
    $decision = $response;
    rejectsResource(static fn() => $authorize($token));
}
$offline = true;
rejectsResource(static fn() => $authorize($token));

$metadata = ResourceAuthorization::metadata($resource, $issuer, $app, ['documents:read', 'documents:read']);
expectResource($metadata === ['resource' => $resource, 'authorization_servers' => [$issuer], 'scopes_supported' => [$scope]], 'Incorrect protected-resource metadata');
$challenge = ResourceAuthorization::challenge($resource, 'invalid_token', 'a"b\\c');
expectResource(str_contains($challenge, 'error_description="a\\"b\\\\c"'), 'Incorrect challenge escaping');
rejectsResource(static fn() => ResourceAuthorization::challenge($resource, 'invalid_token', "bad\r\nheader"));
foreach (['http://resource.example', 'https://user@resource.example', 'https://resource.example/#fragment', 'https://resource.example/?query=1', "https://resource.example/\n"] as $uri) rejectsResource(static fn() => ResourceAuthorization::metadata($uri, $issuer, $app, []));
foreach (['*', 'a:*', 'a::b', '../read', 'a%20b', 'a b', 'roles:member', 'workspaces:read'] as $capability) rejectsResource(static fn() => ResourceAuthorization::capabilityScope($app, $capability));
echo "PHP resource authorization tests passed\n";
