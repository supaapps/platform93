"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

const clearEvent = "p93-clear-credential-notices";
const CredentialContext = createContext<(message: string) => void>(() => {});

export function clearCredentialNotices() {
  globalThis.dispatchEvent(new Event(clearEvent));
}

export function useCredentialNotice() {
  return useContext(CredentialContext);
}

export function CredentialNoticeProvider({ children }: { children: ReactNode }) {
  const [notices, setNotices] = useState<{ id: string; message: string }[]>([]);
  useEffect(() => {
    const clear = () => setNotices([]);
    globalThis.addEventListener(clearEvent, clear);
    return () => globalThis.removeEventListener(clearEvent, clear);
  }, []);
  return <CredentialContext.Provider value={(message) => setNotices((current) => [...current, { id: crypto.randomUUID(), message }])}>
    {children}
    <div className="credential-notices" aria-label="One-time credentials">
      {notices.map((notice) => <section className="toast toast-success credential-notice" role="status" key={notice.id}>
        <div><strong>Save your credential</strong><span>{notice.message}</span><small>Shown once. Keep this private and store it securely before dismissing.</small></div>
        <button aria-label="Dismiss credential notice" onClick={() => setNotices((current) => current.filter((item) => item.id !== notice.id))}>Dismiss</button>
      </section>)}
    </div>
  </CredentialContext.Provider>;
}
