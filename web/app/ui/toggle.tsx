"use client";

import type { InputHTMLAttributes } from "react";

/** Native checked/form behavior with switch semantics for binary settings. */
export function Toggle({ className, ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "role">) {
  return <input {...props} type="checkbox" role="switch" className={`ui-toggle ${className ?? ""}`} />;
}
