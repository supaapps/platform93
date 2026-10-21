<?php
declare(strict_types=1);
require __DIR__.'/../src/ApplicationAdministrationClient.php';

use Supaapps\Platform93\ApplicationAdministrationClient;

$calls=[];
$api=new ApplicationAdministrationClient('https://platform93.test','application',fn():string=>'user-token',function(string $method,string $url,array $headers,?string $body)use(&$calls):array{
    if (!in_array('Authorization: Bearer user-token',$headers,true)||str_contains($url,'/control/')) { throw new RuntimeException('Wrong authority'); }
    $calls[]=[$method,$url,$headers,$body];
    return ['id'=>'created','version'=>1,'invitation_url'=>'https://app.example/invite','email_queued'=>false];
});
$api->createUser(['email'=>'person@example.test','reason'=>'Onboard'],'create-key');
$api->updateUser('created',['first_name'=>'Person','reason'=>'Correct profile'],'"v1"');
$result=$api->createInvitation(['email'=>'person@example.test','onboarding_method'=>'google','send_email'=>false,'reason'=>'Invite'],'invite-key');
if (!in_array('Idempotency-Key: create-key',$calls[0][2],true)||!in_array('If-Match: "v1"',$calls[1][2],true)||$result['email_queued']!==false) { throw new RuntimeException('Missing administrative request constraints'); }
$api->listAssignments('recipient','reader & owner','next',15);
parse_str(parse_url($calls[3][1],PHP_URL_QUERY),$query);
if ($query!==['user_id'=>'recipient','query'=>'reader & owner','cursor'=>'next','limit'=>'15']) { throw new RuntimeException('Pagination lost recipient or query'); }
echo "Application administration SDK checks passed\n";
