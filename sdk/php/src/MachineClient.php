<?php

declare(strict_types=1);

namespace Supaapps\Platform93;

use RuntimeException;

/**
 * @phpstan-type NotificationInput array{template_key:string,user_id?:string,recipient?:string,locale?:string,variables?:array<string,mixed>,attachments?:list<array{filename:string,content_type:string,content_base64:string}>}
 * @phpstan-type QueuedNotification array{id:string,status:'queued'|'suppressed',requested_locale:string,resolved_locale:string,fallback_used:bool}
 * @phpstan-type InvitationInput array{email:string,workspace_id?:string,application_role_keys?:list<string>,workspace_role_keys?:list<string>,expires_in?:int}
 * @phpstan-type Invitation array{id:string,email:string,workspace_id:?string,application_role_keys:list<string>,workspace_role_keys:list<string>,status:string,expires_at:string}
 * @phpstan-type InvitationResent array{id:string,last_sent_at:string,resend_available_at:string,expires_at:string}
 * @phpstan-type User array{id:string,application_id:string,email:string,first_name:string,last_name:string,username:?string,locale:string,email_verified:bool,is_org_verified:bool,status:string,custom_attributes:array<string,mixed>,version:int}
 * @phpstan-type Workspace array{id:string,application_id:string,owner_user_id:string,key:string,name:string,metadata:array<string,mixed>,status:string,version:int,created_at:string,updated_at:string}
 * @phpstan-type WorkspaceAccess array{type:string,workspace_id:string,user_id:?string,email:?string,role_keys:list<string>,invitation_id:?string,status:string,expires_at:?string}
 * @phpstan-type EntitlementGrant array{id:string,subject_type:'user'|'workspace',subject_id:string,source_type:string,feature_values:array<string,mixed>,configuration:array<string,mixed>,starts_at:string,expires_at:?string,external_reference:?string}
 * @phpstan-type BillingSummary array{subject_type:'user'|'workspace',subject_id:string,billing_profile:?array{id:string,name:?string,email:?string,tax_id:?string,version:int},subscriptions:list<array{id:string,price_id:string,provider_id:string,status:string,external_reference:?string}>}
 * @phpstan-type CustomEventInput array{type:string,subject:string,data:array<string,mixed>,correlation_id?:string,causation_id?:string}
 * @phpstan-type PublishedEvent array{id:string,specversion:string,source:string,type:string,subject:string,schema_version:string,data:array<string,mixed>}
 */
final class MachineClient
{
    private ?string $accessToken = null;
    private int $expiresAt = 0;

    /** @param list<string> $scopes */
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $applicationId,
        private readonly string $clientId,
        private string $clientSecret,
        private readonly array $scopes = [],
    ) {
        if ($baseUrl === '' || $applicationId === '' || $clientId === '' || $clientSecret === '') {
            throw new RuntimeException('Platform93 machine client requires base URL, application ID, client ID, and client secret.');
        }
    }

    public function updateSecret(string $secret): void
    {
        if ($secret === '') {
            throw new RuntimeException('Platform93 machine client secret is required.');
        }
        $this->clientSecret = $secret;
        $this->accessToken = null;
        $this->expiresAt = 0;
    }

    /** @param NotificationInput $notification @return QueuedNotification */
    public function sendNotification(array $notification, string $idempotencyKey): array
    {
        return $this->request('POST', '/notifications', $notification, $idempotencyKey);
    }

    /** @param InvitationInput $invitation @return Invitation */
    public function createInvitation(array $invitation): array
    {
        return $this->request('POST', '/invitations', $invitation);
    }

    /** @return array{items:list<Invitation>,next_cursor:?string} */
    public function listInvitations(): array
    {
        return $this->request('GET', '/invitations');
    }

    /** @return Invitation */
    public function getInvitation(string $id): array
    {
        return $this->request('GET', '/invitations/' . rawurlencode($id));
    }

    /** @return InvitationResent */
    public function resendInvitation(string $id): array
    {
        return $this->request('POST', '/invitations/' . rawurlencode($id) . '/resend');
    }

    public function revokeInvitation(string $id): void
    {
        $this->request('DELETE', '/invitations/' . rawurlencode($id));
    }

    /** @return array{items:list<User>,next_cursor:?string} */
    public function listUsers(): array
    {
        return $this->request('GET', '/users');
    }

    /** @return User */
    public function getUser(string $id): array
    {
        return $this->request('GET', '/users/' . rawurlencode($id));
    }

    /** @return array{items:list<Workspace>,next_cursor:?string} */
    public function listWorkspaces(): array
    {
        return $this->request('GET', '/workspaces');
    }

    /** @return Workspace */
    public function getWorkspace(string $id): array
    {
        return $this->request('GET', '/service/workspaces/' . rawurlencode($id));
    }

    /** @return array{items:list<WorkspaceAccess>,next_cursor:?string} */
    public function getWorkspaceAccess(string $id): array
    {
        return $this->request('GET', '/service/workspaces/' . rawurlencode($id) . '/access');
    }

    /** @return array{items:list<EntitlementGrant>,next_cursor:?string} */
    public function getEntitlements(string $subjectType, string $subjectId): array
    {
        return $this->request('GET', '/subjects/' . $this->subject($subjectType, $subjectId) . '/entitlements');
    }

    /** @return BillingSummary */
    public function getBilling(string $subjectType, string $subjectId): array
    {
        return $this->request('GET', '/subjects/' . $this->subject($subjectType, $subjectId) . '/billing');
    }

    /** @param CustomEventInput $event @return PublishedEvent */
    public function publishEvent(array $event, string $idempotencyKey): array
    {
        return $this->request('POST', '/events', $event, $idempotencyKey);
    }

    private function subject(string $type, string $id): string
    {
        if (!in_array($type, ['user', 'workspace'], true)) {
            throw new RuntimeException('Platform93 subject type must be user or workspace.');
        }
        return $type . '/' . rawurlencode($id);
    }

    /** @param array<string,mixed>|null $body @return array<string,mixed> */
    private function request(string $method, string $path, ?array $body = null, ?string $idempotencyKey = null): array
    {
        $headers = ['Accept: application/json', 'Authorization: Bearer ' . $this->token()];
        $content = null;
        if ($body !== null) {
            $content = json_encode($body, JSON_THROW_ON_ERROR);
            $headers[] = 'Content-Type: application/json';
        }
        if ($idempotencyKey !== null) {
            $headers[] = 'Idempotency-Key: ' . $idempotencyKey;
        }
        return $this->http($method, '/v1/applications/' . rawurlencode($this->applicationId) . $path, $headers, $content);
    }

    private function token(): string
    {
        if ($this->accessToken !== null && time() < $this->expiresAt - 30) {
            return $this->accessToken;
        }
        $form = ['grant_type' => 'client_credentials'];
        if ($this->scopes !== []) {
            $form['scope'] = implode(' ', $this->scopes);
        }
        $payload = $this->http('POST', '/oidc/token', [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded',
            'Authorization: Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret),
        ], http_build_query($form));
        if (!isset($payload['access_token']) || !is_string($payload['access_token'])) {
            throw new RuntimeException('Platform93 token response did not contain an access token.');
        }
        $this->accessToken = $payload['access_token'];
        $this->expiresAt = time() + max(1, (int) ($payload['expires_in'] ?? 300));
        return $this->accessToken;
    }

    /** @param list<string> $headers @return array<string,mixed> */
    private function http(string $method, string $path, array $headers, ?string $content): array
    {
        $context = stream_context_create(['http' => [
            'method' => $method,
            'header' => implode("\r\n", $headers),
            'content' => $content ?? '',
            'ignore_errors' => true,
            'timeout' => 30,
        ]]);
        $response = @file_get_contents(rtrim($this->baseUrl, '/') . $path, false, $context);
        $statusLine = $http_response_header[0] ?? 'HTTP/1.1 500';
        preg_match('/\s(\d{3})\s/', $statusLine, $matches);
        $status = (int) ($matches[1] ?? 500);
        if ($response === false || $status < 200 || $status >= 300) {
            throw new RuntimeException(sprintf('Platform93 request returned HTTP %d: %s', $status, substr((string) $response, 0, 4096)));
        }
        if ($response === '') {
            return [];
        }
        $decoded = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        return is_array($decoded) ? $decoded : [];
    }
}
