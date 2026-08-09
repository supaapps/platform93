import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Platform93Auth, type AuthSnapshot } from "@supaapps/platform93-auth";
const Context=createContext<Platform93Auth|null>(null);
export function Platform93Provider({auth,children}:{auth:Platform93Auth;children:ReactNode}){return <Context.Provider value={auth}>{children}</Context.Provider>}
export function usePlatform93Auth(){const auth=useContext(Context);if(!auth)throw new Error("usePlatform93Auth must be used inside Platform93Provider");return auth}
export function usePlatform93Session(){const auth=usePlatform93Auth();const [snapshot,setSnapshot]=useState<AuthSnapshot>(()=>auth.snapshot());useEffect(()=>{const update=()=>setSnapshot(auth.snapshot());auth.addEventListener("change",update);return()=>auth.removeEventListener("change",update)},[auth]);return snapshot}
