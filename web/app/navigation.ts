import { useSyncExternalStore, type MouseEvent } from "react";

const navigationEvent = "platform93:navigation";
const keys = ["context", "organization_id", "application_id", "section", "resource", "id", "panel"] as const;
export type AdminRoute = Partial<Record<typeof keys[number], string>>;

function subscribe(callback: () => void) {
  window.addEventListener("popstate", callback);
  window.addEventListener(navigationEvent, callback);
  return () => {
    window.removeEventListener("popstate", callback);
    window.removeEventListener(navigationEvent, callback);
  };
}

export function useAdminRoute(): AdminRoute {
  const search = useSyncExternalStore(subscribe, () => location.search, () => "");
  const params = new URLSearchParams(search);
  return Object.fromEntries(keys.filter((key) => params.has(key)).map((key) => [key, params.get(key)!]));
}

export function routeHref(patch: AdminRoute, reset = false): string {
  const params = new URLSearchParams(typeof location === "undefined" ? "" : location.search);
  if (reset) keys.forEach((key) => params.delete(key));
  for (const key of Object.keys(patch) as Array<keyof AdminRoute>) {
    const value = patch[key];
    if (value) params.set(key, value);
    else params.delete(key);
  }
  return `/${params.size ? `?${params}` : ""}`;
}

export function navigate(patch: AdminRoute, reset = false, replace = false) {
  const href = routeHref(patch, reset);
  if (href === `${location.pathname}${location.search}`) return;
  history[replace ? "replaceState" : "pushState"](null, "", href);
  window.dispatchEvent(new Event(navigationEvent));
}

export function followRoute(event: MouseEvent<HTMLAnchorElement>, patch: AdminRoute, reset = false) {
  if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  navigate(patch, reset);
}

export function sectionKey(label: string) {
  return label.toLowerCase().replaceAll(" ", "-");
}

export function rememberDestination() {
  const params = new URLSearchParams(location.search);
  const destination = Object.fromEntries(keys.filter((key) => params.has(key)).map((key) => [key, params.get(key)!]));
  if (destination.context) sessionStorage.setItem("p93_admin_destination", JSON.stringify(destination));
}

export function restoreDestination() {
  const saved = sessionStorage.getItem("p93_admin_destination");
  sessionStorage.removeItem("p93_admin_destination");
  if (!saved || new URLSearchParams(location.search).has("context")) return;
  try {
    const parsed = JSON.parse(saved) as AdminRoute;
    const safe = Object.fromEntries(keys.filter((key) => typeof parsed[key] === "string").map((key) => [key, parsed[key]]));
    navigate(safe, true, true);
  } catch { /* Ignore a stale or malformed saved destination. */ }
}
