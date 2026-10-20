<?php
declare(strict_types=1);

namespace Supaapps\Platform93;

use Closure;
use RuntimeException;

/**
 * @phpstan-import-type User from MachineClient
 * @phpstan-import-type InvitationInput from MachineClient
 * @phpstan-type ManagedUserCreate array{email:string,reason:string,first_name?:string,last_name?:string,username?:string,locale?:string,email_verified?:bool,is_org_verified?:bool,custom_attributes?:array<string,mixed>}
 * @phpstan-type ManagedUserUpdate array{reason:string,first_name?:string,last_name?:string,username?:string,locale?:string}
 * @phpstan-type RoleAssignment array{id:string,user_id:?string,role_id:string,workspace_id:?string,role_key?:string,role_scope?:string}
 * @phpstan-type Role array{id:string,key:string,name:string,scope:string,permissions:list<string>}
 * @phpstan-type Session array{id:string,user_agent:?string,authenticated_at:string,expires_at:string,revoked_at:?string,amr:list<string>}
 * @phpstan-type InvitationDelivery array{id:string,invitation_url:string,email_queued:bool,version:int,expires_at:string}
 */
final class ApplicationAdministrationClient
{
    private readonly Closure $token;
    private readonly ?Closure $transport;

    /** @param callable():string $accessToken @param callable(string,string,list<string>,?string):array<string,mixed>|null $transport */
    public function __construct(private readonly string $baseUrl, private readonly string $applicationId, callable $accessToken, ?callable $transport = null)
    {
        $this->token = Closure::fromCallable($accessToken);
        $this->transport = $transport === null ? null : Closure::fromCallable($transport);
    }

    /** @return array{items:list<User>,next_cursor:?string} */
    public function listUsers(string $query = '', ?string $cursor = null, int $limit = 20): array { return $this->request('GET', '/users?' . http_build_query(['query'=>$query,'cursor'=>$cursor,'limit'=>$limit])); }
    /** @return User */
    public function getUser(string $id): array { return $this->request('GET', '/users/' . rawurlencode($id)); }
    /** @param ManagedUserCreate $input @return User */
    public function createUser(array $input, string $idempotencyKey): array { return $this->request('POST', '/users', $input, $idempotencyKey); }
    /** @param ManagedUserUpdate $input */
    public function updateUser(string $id, array $input, string $etag): void { $this->request('PATCH', '/users/' . rawurlencode($id), $input, null, $etag); }
    /** @param array<string,mixed> $attributes */
    public function updateAttributes(string $id, array $attributes, string $reason, string $etag): void { $this->request('PATCH', '/users/' . rawurlencode($id) . '/attributes', ['custom_attributes'=>(object)$attributes,'reason'=>$reason], null, $etag); }
    public function changeUserState(string $id, string $action, string $reason, string $etag, string $idempotencyKey): void
    {
        if (!in_array($action, ['suspend','restore','verify-email','unverify-email','verify-organization','unverify-organization','sessions/revoke'], true)) { throw new RuntimeException('Invalid administration action.'); }
        $this->request('POST', '/users/' . rawurlencode($id) . '/' . $action, ['reason'=>$reason], $idempotencyKey, $etag);
    }
    /** @return array{items:list<Session>,next_cursor:?string} */
    public function listSessions(string $id): array { return $this->request('GET', '/users/' . rawurlencode($id) . '/sessions'); }
    /** @return array{items:list<Role>,next_cursor:?string} */
    public function listRoles(): array { return $this->request('GET', '/roles'); }
    /** @return array{items:list<RoleAssignment>,next_cursor:?string,user_version:int} */
    public function listAssignments(string $userId): array { return $this->request('GET', '/role-assignments?user_id=' . rawurlencode($userId)); }
    /** @return RoleAssignment */
    public function assignRole(string $userId, string $roleId, ?string $workspaceId, string $reason, string $etag, string $idempotencyKey): array
    {
        $input = ['user_id'=>$userId,'role_id'=>$roleId,'reason'=>$reason];
        if ($workspaceId !== null) { $input['workspace_id']=$workspaceId; }
        return $this->request('POST', '/role-assignments', $input, $idempotencyKey, $etag);
    }
    public function removeRole(string $id, string $reason, string $etag): void { $this->request('DELETE', '/role-assignments/' . rawurlencode($id), ['reason'=>$reason], null, $etag); }
    /** @param InvitationInput $input @return InvitationDelivery */
    public function createInvitation(array $input, string $idempotencyKey): array { return $this->request('POST', '/invitations', $input, $idempotencyKey); }
    /** @return InvitationDelivery */
    public function rotateInvitation(string $id, bool $sendEmail, string $reason, string $etag, string $idempotencyKey): array { return $this->request('POST', '/invitations/' . rawurlencode($id) . '/rotate', ['send_email'=>$sendEmail,'reason'=>$reason], $idempotencyKey, $etag); }
    public function revokeInvitation(string $id, string $reason, string $etag): void { $this->request('DELETE', '/invitations/' . rawurlencode($id), ['reason'=>$reason], null, $etag); }

    /** @param array<string,mixed>|null $body @return array<string,mixed> */
    private function request(string $method, string $path, ?array $body=null, ?string $key=null, ?string $etag=null): array
    {
        $headers=['Accept: application/json','Authorization: Bearer ' . ($this->token)()];
        if ($key!==null) { $headers[]='Idempotency-Key: ' . $key; }
        if ($etag!==null) { $headers[]='If-Match: ' . $etag; }
        $content=$body===null?null:json_encode($body, JSON_THROW_ON_ERROR);
        if ($content!==null) { $headers[]='Content-Type: application/json'; }
        $url=rtrim($this->baseUrl,'/') . '/v1/applications/' . rawurlencode($this->applicationId) . $path;
        if ($this->transport!==null) { return ($this->transport)($method,$url,$headers,$content); }
        $result=file_get_contents($url,false,stream_context_create(['http'=>['method'=>$method,'header'=>implode("\r\n",$headers),'content'=>$content??'','ignore_errors'=>true,'timeout'=>30,'follow_location'=>0]]));
        $status=0;
        foreach ($http_response_header??[] as $header) { if (preg_match('/^HTTP\/\S+\s+(\d+)/',$header,$match)) { $status=(int)$match[1]; } }
        if ($result===false||$status<200||$status>=300) { throw new RuntimeException('Platform93 administration request failed with HTTP ' . $status); }
        return $result===''?[]:json_decode($result,true,512,JSON_THROW_ON_ERROR);
    }
}
