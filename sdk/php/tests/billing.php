<?php
declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';

use Supaapps\Platform93\MachineClient;

$client = new MachineClient('https://platform93.example', 'app', 'machine', 'fixture', [],
    static function (string $method, string $url, array $headers, ?string $body): array {
        if (str_ends_with($url, '/oidc/token')) return ['access_token' => 'machine', 'expires_in' => 300];
        if (str_ends_with($url, '/billing/cancel')) {
            if ($method !== 'POST' || !in_array('Idempotency-Key: cancel-key', $headers, true)
                || json_decode((string) $body, true, 32, JSON_THROW_ON_ERROR) !== ['at_period_end' => false]) {
                throw new RuntimeException('Cancellation request did not preserve its body/key.');
            }
            return [];
        }
        return ['subscriptions' => [['provider_subscription_id' => 'sub_fixture', 'past_due_since' => '2026-10-01T00:00:00Z']]];
    });
$summary = $client->getBilling('workspace', 'workspace');
if ($summary['subscriptions'][0]['provider_subscription_id'] !== 'sub_fixture') {
    throw new RuntimeException('Billing summary lost its provider identifier.');
}
$client->cancelWorkspaceBilling('workspace', 'cancel-key', false);
echo "Machine billing contracts pass\n";
