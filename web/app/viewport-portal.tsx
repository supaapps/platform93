"use client";

import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

export function ViewportPortal({ children }: { children: ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  // Body-level overlays cannot be clipped or repositioned by animated page ancestors.
  return mounted ? createPortal(children, document.body) : null;
}
