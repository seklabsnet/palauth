"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import type { ApiKey } from "@/lib/api";
import { toast } from "sonner";

interface ApiKeyDisplayProps {
  apiKey: ApiKey;
  onRotate?: () => void;
  showRotate?: boolean;
}

export function ApiKeyDisplay({
  apiKey,
  onRotate,
  showRotate,
}: ApiKeyDisplayProps) {
  const [revealed, setRevealed] = useState(false);

  const displayValue = apiKey.plaintext
    ? revealed
      ? apiKey.plaintext
      : `${apiKey.prefix}${"*".repeat(32)}`
    : `${apiKey.prefix}${"*".repeat(32)}`;

  function handleCopy() {
    if (apiKey.plaintext) {
      navigator.clipboard.writeText(apiKey.plaintext);
      toast.success("Copied to clipboard");
    }
  }

  return (
    <div className="rounded-lg border p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium capitalize">
          {apiKey.key_type.replace("_", " ")}
        </span>
        <div className="flex gap-1">
          {apiKey.plaintext && (
            <>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setRevealed(!revealed)}
              >
                {revealed ? "Hide" : "Reveal"}
              </Button>
              <Button variant="ghost" size="sm" onClick={handleCopy}>
                Copy
              </Button>
            </>
          )}
          {showRotate && onRotate && (
            <Button variant="ghost" size="sm" onClick={onRotate}>
              Rotate
            </Button>
          )}
        </div>
      </div>
      <code className="block break-all rounded bg-muted p-2 text-xs">
        {displayValue}
      </code>
    </div>
  );
}
