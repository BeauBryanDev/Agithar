import { useState, type FormEvent } from "react";
import { Search } from "lucide-react";
import { Button } from "../common/Button";

interface CVESearchBarProps {
  onSearch: (query: string) => void;
  loading: boolean;
}

export function CVESearchBar({ onSearch, loading }: CVESearchBarProps) {
  const [value, setValue] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSearch(value.trim());
  };

  return (
    <form onSubmit={submit} className="flex gap-2">
      <div className="relative flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-dim" />
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Enter a CVE ID, for example CVE-2021-44228"
          className="w-full border border-hairline bg-panel-2 py-2.5 pl-10 pr-3 font-mono text-sm text-primary placeholder:text-dim focus:border-electric focus:outline-none"
        />
      </div>
      <Button type="submit" disabled={loading}>
        {loading ? "Searching…" : "Search"}
      </Button>
    </form>
  );
}
