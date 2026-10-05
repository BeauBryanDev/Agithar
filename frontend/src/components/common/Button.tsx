import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "ghost" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  children: ReactNode;
}

const base =
  "inline-flex items-center justify-center gap-2 rounded-sm px-4 py-2 text-sm font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed select-none";

const variants: Record<Variant, string> = {
  primary:
    "bg-electric text-void hover:bg-neon border border-electric hover:border-neon",
  ghost:
    "bg-transparent text-secondary hover:text-primary border border-hairline hover:border-electric",
  danger:
    "bg-transparent text-sev-critical border border-hairline hover:border-sev-critical",
};

export function Button({
  variant = "primary",
  children,
  className = "",
  ...rest
}: ButtonProps) {
  return (
    <button className={`${base} ${variants[variant]} ${className}`} {...rest}>
      {children}
    </button>
  );
}
