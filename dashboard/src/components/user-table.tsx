"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Input } from "@/components/ui/input";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import * as api from "@/lib/api";
import { toast } from "sonner";

interface UserTableProps {
  projectId: string;
}

export function UserTable({ projectId }: UserTableProps) {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [bannedFilter, setBannedFilter] = useState<string | undefined>();
  const [cursor, setCursor] = useState<{
    created_at: string;
    id: string;
  } | null>(null);
  const [banDialog, setBanDialog] = useState<api.User | null>(null);
  const [banReason, setBanReason] = useState("");
  const [deleteDialog, setDeleteDialog] = useState<api.User | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["users", projectId, search, bannedFilter, cursor],
    queryFn: () =>
      api.listUsers(projectId, {
        limit: 20,
        email: search || undefined,
        banned: bannedFilter,
        cursor_created_at: cursor?.created_at,
        cursor_id: cursor?.id,
      }),
  });

  const banMutation = useMutation({
    mutationFn: ({ userId, reason }: { userId: string; reason: string }) =>
      api.banUser(projectId, userId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users", projectId] });
      setBanDialog(null);
      setBanReason("");
      toast.success("User banned");
    },
    onError: (err) => {
      toast.error(err instanceof api.ApiError ? err.description : "Ban failed");
    },
  });

  const unbanMutation = useMutation({
    mutationFn: (userId: string) => api.unbanUser(projectId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users", projectId] });
      toast.success("User unbanned");
    },
  });

  const resetPwMutation = useMutation({
    mutationFn: (userId: string) =>
      api.resetUserPassword(projectId, userId),
    onSuccess: () => {
      toast.success("Password reset initiated");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (userId: string) => api.deleteUser(projectId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users", projectId] });
      setDeleteDialog(null);
      toast.success("User deleted");
    },
  });

  const users = data?.users ?? [];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-2">
        <Input
          placeholder="Search by email..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setCursor(null);
          }}
          className="max-w-sm"
        />
        <DropdownMenu>
          <DropdownMenuTrigger render={<Button variant="outline" />}>
              {bannedFilter === "true"
                ? "Banned"
                : bannedFilter === "false"
                  ? "Active"
                  : "All Users"}
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem
              onClick={() => {
                setBannedFilter(undefined);
                setCursor(null);
              }}
            >
              All Users
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => {
                setBannedFilter("false");
                setCursor(null);
              }}
            >
              Active
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => {
                setBannedFilter("true");
                setCursor(null);
              }}
            >
              Banned
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Table */}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Email</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Verified</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8">
                  Loading...
                </TableCell>
              </TableRow>
            ) : users.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8">
                  No users found
                </TableCell>
              </TableRow>
            ) : (
              users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">{user.email}</TableCell>
                  <TableCell>
                    {user.banned ? (
                      <Badge variant="destructive">Banned</Badge>
                    ) : (
                      <Badge variant="secondary">Active</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {user.email_verified ? (
                      <Badge variant="secondary">Verified</Badge>
                    ) : (
                      <Badge variant="outline">Unverified</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {new Date(user.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger render={<Button variant="ghost" size="sm" />}>
                          Actions
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {user.banned ? (
                          <DropdownMenuItem
                            onClick={() => unbanMutation.mutate(user.id)}
                          >
                            Unban
                          </DropdownMenuItem>
                        ) : (
                          <DropdownMenuItem
                            onClick={() => setBanDialog(user)}
                          >
                            Ban
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuItem
                          onClick={() => resetPwMutation.mutate(user.id)}
                        >
                          Reset Password
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-destructive"
                          onClick={() => setDeleteDialog(user)}
                        >
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
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

      {/* Ban Dialog */}
      <Dialog open={!!banDialog} onOpenChange={() => setBanDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Ban User</DialogTitle>
            <DialogDescription>
              Ban {banDialog?.email}? They will not be able to log in.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="ban-reason">Reason</Label>
            <Input
              id="ban-reason"
              value={banReason}
              onChange={(e) => setBanReason(e.target.value)}
              placeholder="Reason for ban"
              required
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBanDialog(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={!banReason || banMutation.isPending}
              onClick={() =>
                banDialog &&
                banMutation.mutate({
                  userId: banDialog.id,
                  reason: banReason,
                })
              }
            >
              {banMutation.isPending ? "Banning..." : "Ban User"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog
        open={!!deleteDialog}
        onOpenChange={() => setDeleteDialog(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete User</DialogTitle>
            <DialogDescription>
              This action cannot be undone. Delete {deleteDialog?.email}?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialog(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={() =>
                deleteDialog && deleteMutation.mutate(deleteDialog.id)
              }
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete User"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
