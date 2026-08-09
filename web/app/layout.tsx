import type { Metadata } from "next";
import "./styles.css";
export const metadata:Metadata={title:"Platform93",description:"Self-hosted identity, billing, and application control"};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
