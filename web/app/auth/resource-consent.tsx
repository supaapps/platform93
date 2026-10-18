import { useState } from "react";

export type ResourceConsent = {
  resource: { id: string; uri: string; name: string };
  capabilities: { key: string; name: string; context: "personal" | "workspace" }[];
  workspaces: { id: string; name: string; key: string }[];
  personal_access_available: boolean;
};

export function ResourceConsentForm({ consent, disabled, approve }: { consent: ResourceConsent; disabled: boolean; approve: (body: object) => void }) {
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [personal, setPersonal] = useState(false);
  const [workspaces, setWorkspaces] = useState<string[]>([]);
  const personalSelected = consent.capabilities.some((item) => item.context === "personal" && capabilities.includes(item.key));
  const workspaceSelected = consent.capabilities.some((item) => item.context === "workspace" && capabilities.includes(item.key));
  const valid = capabilities.length > 0 && (!personalSelected || personal) && (!workspaceSelected || workspaces.length > 0);
  function toggle(values: string[], key: string, checked: boolean) { return checked ? [...values, key] : values.filter((value) => value !== key); }
  return <form className="hosted-resource-consent" onSubmit={(event) => {
    event.preventDefault();
    if (disabled || !valid) return;
    approve({ action: "approve", approved_capabilities: capabilities, personal_access: personalSelected && personal, workspace_ids: workspaceSelected ? workspaces : [] });
  }}>
    <p><strong>{consent.resource.name}</strong><small>{consent.resource.uri}</small></p>
    <p>Select only the capabilities and access contexts you want to share. Nothing is selected automatically.</p>
    <fieldset disabled={disabled}><legend>Capabilities</legend>{consent.capabilities.map((item) => <label key={item.key}><input type="checkbox" checked={capabilities.includes(item.key)} disabled={item.context === "personal" ? !consent.personal_access_available : !consent.workspaces.length} onChange={(event) => setCapabilities(toggle(capabilities, item.key, event.target.checked))} /><span>{item.name}<small>{item.key} · {item.context === "personal" ? "Personal access" : "Selected workspaces"}</small></span></label>)}</fieldset>
    {consent.personal_access_available && <fieldset disabled={disabled}><legend>Personal context</legend><label><input type="checkbox" checked={personal} onChange={(event) => setPersonal(event.target.checked)} /><span>Allow personal access</span></label></fieldset>}
    {consent.workspaces.length > 0 && <fieldset disabled={disabled}><legend>Workspaces</legend>{consent.workspaces.map((workspace) => <label key={workspace.id}><input type="checkbox" checked={workspaces.includes(workspace.id)} onChange={(event) => setWorkspaces(toggle(workspaces, workspace.id, event.target.checked))} /><span>{workspace.name}<small>{workspace.key}</small></span></label>)}</fieldset>}
    {!valid && <p>Select at least one capability and explicitly choose its personal or workspace context to continue.</p>}
    <button className="hosted-primary" disabled={disabled || !valid}>Approve selected access</button>
  </form>;
}
