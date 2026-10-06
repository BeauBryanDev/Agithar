import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

// Raw HTML is never rendered (react-markdown's default) and images are
// dropped, so text copied from a log cannot load a remote picture.
const SAFE_LINK = /^https:\/\//i;

const components: Components = {
  p: ({ children }) => <p className="my-1.5 first:mt-0 last:mb-0">{children}</p>,
  strong: ({ children }) => (
    <strong className="font-semibold text-neon">{children}</strong>
  ),
  em: ({ children }) => <em className="italic">{children}</em>,
  ul: ({ children }) => (
    <ul className="my-1.5 list-disc space-y-0.5 pl-5">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="my-1.5 list-decimal space-y-0.5 pl-5">{children}</ol>
  ),
  h1: ({ children }) => (
    <h3 className="mb-1 mt-3 text-base font-semibold text-neon">{children}</h3>
  ),
  h2: ({ children }) => (
    <h3 className="mb-1 mt-3 text-base font-semibold text-neon">{children}</h3>
  ),
  h3: ({ children }) => (
    <h4 className="mb-1 mt-2 text-base font-semibold text-primary">{children}</h4>
  ),
  code: ({ children }) => (
    <code className="rounded-sm border border-hairline bg-panel-2 px-1 py-0.5 font-mono text-[13px] text-electric">
      {children}
    </code>
  ),
  pre: ({ children }) => (
    <pre className="hud-corners my-2 overflow-x-auto border border-hairline bg-panel-2 p-3 font-mono text-[13px] text-secondary [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0">
      {children}
    </pre>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-2 border-l-2 border-electric pl-3 text-secondary">
      {children}
    </blockquote>
  ),
  table: ({ children }) => (
    <div className="my-2 overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="border border-hairline bg-panel-2 px-2 py-1 text-left font-medium">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="border border-hairline px-2 py-1">{children}</td>
  ),
  hr: () => <hr className="my-3 border-hairline" />,
  a: ({ href, children }) =>
    href && SAFE_LINK.test(href) ? (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        className="text-electric underline"
      >
        {children}
      </a>
    ) : (
      <span>{children}</span>
    ),
  img: () => null,
};

interface MarkdownTextProps {
  content: string;
  streaming?: boolean;
}

export function MarkdownText({ content, streaming }: MarkdownTextProps) {
  return (
    <div className="break-words text-base leading-relaxed text-primary">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
      {streaming && <span className="aegis-cursor" />}
    </div>
  );
}
