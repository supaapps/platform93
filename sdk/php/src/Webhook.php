<?php
declare(strict_types=1);
namespace Supaapps\Platform93;
final class Webhook {
    public const PLATFORM_EVENT_VERSIONS = [
        'organization.created'=>'1.0','organization.retired'=>'1.0','organization.restored'=>'1.0',
        'application.created'=>'1.0','application.retired'=>'1.0','application.restored'=>'1.0',
        'delegation.created'=>'1.0','delegation.exchanged'=>'1.0','delegation.revoked'=>'1.0',
        'entitlement.granted'=>'1.0','local_entitlement_request.created'=>'1.0','local_entitlement_request.approved'=>'1.0',
        'oauth.consent_revoked'=>'1.0','platform93.webhook.test'=>'1.0','user.created'=>'1.0',
        'user.email_verified'=>'1.0','user.email_unverified'=>'1.0','user.organization_verified'=>'1.0',
        'user.organization_unverified'=>'1.0','user.email_changed'=>'1.0','user.password_reset'=>'1.0',
        'user.pending_deletion'=>'1.0','user.anonymized'=>'1.0','user.deleted'=>'1.0',
        'user.suspended'=>'1.0','user.restored'=>'1.0','workspace.invitation_created'=>'1.0',
        'workspace.invitation_accepted'=>'1.0','workspace.owner_transferred'=>'1.0',
    ];

    public static function verify(string $rawBody, string $header, string $secret, int $tolerance = 300): array {
        $parts=[]; foreach(explode(',', $header) as $part){[$key,$value]=array_pad(explode('=', $part, 2),2,'');$parts[$key]=$value;}
        $timestamp=(int)($parts['t']??0); if($timestamp===0||abs(time()-$timestamp)>$tolerance) throw new \UnexpectedValueException('Platform93 webhook timestamp rejected');
        $expected=hash_hmac('sha256',$timestamp.'.'.$rawBody,$secret); if(!hash_equals($expected,(string)($parts['v1']??''))) throw new \UnexpectedValueException('Platform93 webhook signature rejected');
        $event=json_decode($rawBody,true,64,JSON_THROW_ON_ERROR);
        if(($event['specversion']??null)!=='1.0'||!is_string($event['type']??null)||!in_array($event['contract_source']??null,['platform93','application'],true)||!is_string($event['schema_version']??null)||!is_array($event['data']??null)) throw new \UnexpectedValueException('Platform93 webhook envelope rejected');
        return $event;
    }

    public static function isPlatformEvent(array $event): bool { return ($event['contract_source']??null)==='platform93'&&isset(self::PLATFORM_EVENT_VERSIONS[$event['type']??'']); }
    public static function isCustomEvent(array $event): bool { return ($event['contract_source']??null)==='application'; }
    public static function assertSupportedPlatformEvent(array $event): void {
        if(!self::isPlatformEvent($event)) throw new \UnexpectedValueException('Unknown Platform93 event contract');
        $supported=self::PLATFORM_EVENT_VERSIONS[$event['type']];
        if(explode('.',$supported,2)[0]!==explode('.',$event['schema_version'],2)[0]) throw new \UnexpectedValueException('Unsupported Platform93 event schema version');
    }
}
