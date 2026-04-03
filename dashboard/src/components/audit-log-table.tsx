"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import * as api from "@/lib/api";
import { toast } from "sonner";

const EVENT_TYPES = [
  "",
  "auth.signup",
  "auth.login",
  "auth.login.failed",
  "auth.logout",
  "auth.password.reset",
  "auth.password.change",
  "auth.email.verify",
  "admin.user.create",
  "admin.user.update",
  "admin.user.delete",
  "admin.user.ban",
  "admin.user.unban",
  "admin.user.reset_password",
  "gdpr.erasure",
];

interface AuditLogTableProps {
  projectId: string;
}

export function AuditLogTable({ projectId }: AuditLogTableProps) {
  const [eventType, setEventType] = useState("");
  const [cursor, setCursor] = useState<{
    created_at: string;
    id: string;
  } | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["audit-logs", projectId, eventType, cursor],
    queryFn: () =>
      api.listAuditLogs(projectId, {
        limit: 50,
        event_type: eventType || undefined,
        cursor_time: cursor?.created_at,
        cursor_id: cursor?.id,
      }),
  });

  const verifyMutation = useMutation({
    mutationFn: () => api.verifyAuditLogs(projectId),
  });

  async function handleExport(format: "json" | "csv") {
    try {
      const blob = await api.exportAuditLogs(projectId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `audit_logs.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch {
      toast.error("Export failed");
    }
  }

  const entries = data?.entries ?? [];

  return (
    <div className="space-y-4">
      {/* Filters & Actions */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="outline" />}>
                {eventType || "All Events"}
            </DropdownMenuTrigger>
            <DropdownMenuContent className="max-h-64 overflow-y-auto">
              {EVENT_TYPES.map((et) => (
                <DropdownMenuItem
                  key={et}
                  onClick={() => {
                    setEventType(et);
                    setCursor(null);
                  }}
                >
                  {et || "All Events"}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => verifyMutation.mutate()}
            disabled={verifyMutation.isPending}
          >
            {verifyMutation.isPending ? "Verifying..." : "Verify Integrity"}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="outline" />}>
              Export
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => handleExport("json")}>
                JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport("csv")}>
                CSV
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Verify Result */}
      {verifyMutation.data && (
        <Alert variant={verifyMutation.data.valid ? "default" : "destructive"}>
          <AlertTitle>
            {verifyMutation.data.valid
              ? "Integrity Verified"
              : "Integrity Broken"}
          </AlertTitle>
          <AlertDescription>
            {verifyMutation.data.valid
              ? `All ${verifyMutation.data.total_entries} entries verified successfully.`
              : `Chain broken at entry ${verifyMutation.data.broken_at_index} (${verifyMutation.data.broken_at_id}). ${verifyMutation.data.verified_entries} of ${verifyMutation.data.total_entries} entries verified.`}
          </AlertDescription>
        </Alert>
      )}

      {/* Table */}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Event</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-8">
                  Loading...
                </TableCell>
              </TableRow>
            ) : entries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-8">
                  No audit log entries found
                </TableCell>
              </TableRow>
            ) : (
              entries.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell>
                    <Badge variant="outline">{entry.event_type}</Badge>
                  </TableCell>
                  <TableCell className="text-sm">
                    <span className="text-muted-foreground">
                      {entry.target_type}
                    </span>{" "}
                    <span className="font-mono text-xs">
                      {entry.target_id.length > 16 ? `${entry.target_id.slice(0, 16)}...` : entry.target_id}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {entry.actor_id
                      ? entry.actor_id.length > 16
                        ? `${entry.actor_id.slice(0, 16)}...`
                        : entry.actor_id
                      : "-"}
                  </TableCell>
                  <TableCell className="text-sm">
                    {new Date(entry.created_at).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {data?.next_cursor && (
        <div className="flex justify-end">
          <Button
            variant="outline"
            onClick={() => setCursor(data.next_cursor!)}
          >
            Next Page
          </Button>
        </div>
      )}
    </div>
  );
}
