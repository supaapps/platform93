import assert from "node:assert/strict";
import test from "node:test";
import { Platform93Client } from "./dist/index.js";

test("application administration uses the user bearer, versions and idempotency without control routes", async () => {
  const calls=[];
  const client=new Platform93Client({baseUrl:"https://platform93.test",applicationId:"application",accessToken:()=>"application-user-token",fetch:async(url,init)=>{
    calls.push({url,init,body:init.body?JSON.parse(init.body):undefined});
    assert.ok(!url.includes("/control/"));assert.equal(init.headers.Authorization,"Bearer application-user-token");
    return init.method==="PATCH"||init.method==="DELETE"?new Response(null,{status:204}):Response.json({id:"user",version:1,invitation_url:"https://app.example/invitation?link_token=one-time",email_queued:false});
  }});
  const admin=client.application().administration();
  await admin.createUser({email:"person@example.test",reason:"Onboard"},"create-onboarding");
  await admin.updateUser("user",{first_name:"Person",reason:"Correct profile"},'"v1"');
  await admin.createInvitation({email:"person@example.test",onboarding_method:"google",send_email:false,reason:"Invite colleague"},"invite-onboarding");
  await admin.rotateInvitation("invitation",{send_email:false,reason:"Send manually"},'"v1"',"rotate-onboarding");
  assert.equal(calls[0].init.headers["Idempotency-Key"],"create-onboarding");
  assert.equal(calls[1].init.headers["If-Match"],'"v1"');
  assert.equal(calls[2].body.send_email,false);
  assert.equal(calls[3].init.headers["If-Match"],'"v1"');
});
