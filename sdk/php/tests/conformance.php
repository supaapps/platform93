<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/Webhook.php';

use Supaapps\Platform93\Webhook;

$fixture = json_decode((string) file_get_contents(__DIR__ . '/../../../conformance/webhook.json'), true, 32, JSON_THROW_ON_ERROR);
$event = Webhook::verify($fixture['raw_body'], $fixture['signature'], $fixture['secret'], 1_000_000_000);
if (($event['id'] ?? null) !== '01900000-0000-7000-8000-000000000001') {
    throw new RuntimeException('Shared webhook fixture failed.');
}
if (!Webhook::isPlatformEvent($event)) throw new RuntimeException('Platform event discrimination failed.');
Webhook::assertSupportedPlatformEvent($event);
