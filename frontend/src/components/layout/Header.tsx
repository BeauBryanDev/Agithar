import { Link } from "react-router-dom";
import { LogOut } from "lucide-react";
import { HealthReadout } from "./HealthReadout";
import dragon from "../../assets/dragon-avatar.webp";
import shield from "../../assets/shield.svg";
import claude from "../../assets/Claude.png";
import openai from "../../assets/OpenAI_icon.svg";
import python from "../../assets/Python.svg";
import fastapi from "../../assets/FastAPI.svg";
import sklearn from "../../assets/scikit-learn.svg";
import pytorch from "../../assets/PyTorch.svg";
import postgres from "../../assets/PostgresSQL.svg";
import langchain from "../../assets/LangChain.png";
import bash from "../../assets/Bash.svg";
import ubuntu from "../../assets/Ubuntu.svg";
import aws from "../../assets/AWS.svg";
import typescript from "../../assets/Typescript.svg";
import react from "../../assets/React.svg";
import tailwind from "../../assets/Tailwindcss.svg";
import vite from "../../assets/Vite.svg";

// Left to right, as shown in the header.
const STACK = [
  { name: "Python", src: python },
  { name: "FastAPI", src: fastapi },
  { name: "scikit-learn", src: sklearn },
  { name: "PyTorch", src: pytorch },
  { name: "PostgreSQL", src: postgres },
  { name: "LangChain", src: langchain },
  { name: "Bash", src: bash },
  { name: "Ubuntu", src: ubuntu },
  { name: "AWS", src: aws },
  { name: "TypeScript", src: typescript },
  { name: "React", src: react },
  { name: "Tailwind CSS", src: tailwind },
  { name: "Vite", src: vite },
];

interface HeaderProps {
  detectorsActive: boolean;
  username: string;
  onSignOut: () => void;
  /** The public demo: no account, no profile link, the visitor's own model. */
  guest?: boolean;
}

export function Header({
  detectorsActive,
  username,
  onSignOut,
  guest = false,
}: HeaderProps) {
  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-hairline bg-panel px-5">
      <div className="flex items-center gap-3">
        <span className="font-mono text-xs uppercase tracking-[0.2em] text-secondary">
          {guest ? "Blue-Team Public Demo" : "Blue-Team Analysis Console"}
        </span>
        <span className="hidden h-4 w-px bg-hairline xl:block" />
        <ul className="hidden items-center gap-3 xl:flex">
          {STACK.map((t) => (
            <li key={t.name}>
              <img
                src={t.src}
                alt={t.name}
                title={t.name}
                className="h-5 w-5 object-contain opacity-80 transition-opacity hover:opacity-100"
              />
            </li>
          ))}
        </ul>
      </div>

      <div className="flex items-center gap-5">
        {/* Active model */}
        <div className="hidden items-center gap-2 sm:flex">
          <img
            src={guest ? openai : claude}
            alt={guest ? "OpenAI" : "Claude"}
            className="h-5 w-5 rounded-sm"
          />
          <span className="font-mono text-[11px] uppercase tracking-wider text-secondary">
            Powered by{" "}
            <span className="text-electric">
              {guest ? "GPT-6-luna" : "Claude-Sonnet-5.5"}
            </span>
          </span>
        </div>

        <span className="hidden h-4 w-px bg-hairline sm:block" />

        {!guest && (
          <>
            <HealthReadout />
            <span className="h-4 w-px bg-hairline" />
          </>
        )}

        {/* Live indicator */}
        <div className="flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${
              detectorsActive
                ? "aegis-live-dot bg-neon"
                : "bg-dim"
            }`}
          />
          <span className="font-mono text-[11px] uppercase tracking-wider text-secondary">
            {detectorsActive ? "Detectors active" : "Idle"}
          </span>
        </div>

        <span className="h-4 w-px bg-hairline" />

        {/* Signed-in user */}
        <div className="flex items-center gap-2">
          {guest ? (
            <span className="border border-hairline px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-neon">
              Guest
            </span>
          ) : (
            <>
              <img
                src={dragon}
                alt=""
                className="h-6 w-6 rounded-sm object-contain"
              />
              <Link
                to="/profile"
                title="My profile"
                className="font-mono text-xs text-secondary transition-colors hover:text-neon"
              >
                {username}
              </Link>
            </>
          )}
          <button
            onClick={onSignOut}
            title={guest ? "Leave the demo" : "Sign out"}
            className="text-dim transition-colors hover:text-primary"
          >
            <LogOut className="h-3.5 w-3.5" strokeWidth={1.75} />
          </button>
        </div>

        <span className="h-4 w-px bg-hairline" />

        <img src={shield} alt="Aegis Cyber SOC" className="h-8 w-8" />
      </div>
    </header>
  );
}
