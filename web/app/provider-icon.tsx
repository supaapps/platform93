export function ProviderIcon({ provider }: { provider: string }) {
  return <svg className="provider-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    {provider === "google" && <><path fill="#4285F4" d="M21.6 12.2c0-.7-.1-1.4-.2-2.1H12v4h5.4a4.6 4.6 0 0 1-2 3v2.5h3.2c1.9-1.8 3-4.3 3-7.4Z"/><path fill="#34A853" d="M12 22c2.7 0 5-.9 6.6-2.4l-3.2-2.5c-.9.6-2 1-3.4 1-2.6 0-4.8-1.8-5.6-4.2H3.1v2.6A10 10 0 0 0 12 22Z"/><path fill="#FBBC05" d="M6.4 13.9a6 6 0 0 1 0-3.8V7.5H3.1a10 10 0 0 0 0 9l3.3-2.6Z"/><path fill="#EA4335" d="M12 5.9c1.5 0 2.8.5 3.8 1.5l2.9-2.8A9.6 9.6 0 0 0 12 2a10 10 0 0 0-8.9 5.5l3.3 2.6A5.9 5.9 0 0 1 12 5.9Z"/></>}
    {provider === "microsoft" && <><path fill="#F25022" d="M2 2h9v9H2z"/><path fill="#7FBA00" d="M13 2h9v9h-9z"/><path fill="#00A4EF" d="M2 13h9v9H2z"/><path fill="#FFB900" d="M13 13h9v9h-9z"/></>}
    {provider === "apple" && <path fill="currentColor" d="M17 12.5c0-2 1.6-3 1.7-3.1-1-1.4-2.5-1.6-3-1.6-1.3-.2-2.6.8-3.3.8-.7 0-1.8-.8-2.9-.8-1.5 0-2.9.9-3.7 2.2-1.6 2.7-.4 6.7 1.1 8.9.7 1 1.5 2.1 2.6 2 1.1 0 1.5-.7 2.8-.7s1.7.7 2.9.7c1.2 0 1.9-1 2.6-2 1-1.5 1.5-2.9 1.5-3-2.3-1-2.3-3.3-2.3-3.4ZM14.8 6.4c.6-.8 1.1-1.9 1-3-.9.1-2 .6-2.7 1.4-.6.7-1.2 1.9-1 2.9 1 .1 2.1-.5 2.7-1.3Z"/>}
    {provider === "facebook" && <><circle cx="12" cy="12" r="11" fill="#1877F2"/><path fill="white" d="M13.6 22v-8h2.7l.4-3h-3.1V9.1c0-.8.3-1.4 1.5-1.4h1.7V5c-.3 0-1.3-.1-2.5-.1-2.4 0-4 1.4-4 4.1v2H7.7v3h2.6v8z"/></>}
    {provider === "linkedin" && <><rect x="1" y="1" width="22" height="22" rx="2" fill="#0A66C2"/><path fill="white" d="M5 9h3v10H5zm1.5-4a1.7 1.7 0 1 1 0 3.4 1.7 1.7 0 0 1 0-3.4ZM10 9h3v1.4c.5-.9 1.5-1.6 3-1.6 3.2 0 3.5 2 3.5 4.5V19h-3v-5c0-1.2 0-2.5-1.6-2.5s-1.9 1.3-1.9 2.4V19h-3Z"/></>}
  </svg>;
}
