"use client";

import { use, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { StatCard } from "@/components/stat-card";
import { UserTable } from "@/components/user-table";
import { ApiKeyDisplay } from "@/components/api-key-display";
import { AuditLogTable } from "@/components/audit-log-table";
import * as api from "@/lib/api";
import { toast } from "sonner";

export default function ProjectDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);

  return <ProjectDetail projectId={id} />;
}

function ProjectDetail({ projectId }: { projectId: string }) {
  const { data: project, isLoading } = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => api.getProject(projectId),
  });

  const { data: analytics } = useQuery({
    queryKey: ["analytics", projectId],
    queryFn: () => api.getProjectAnalytics(projectId),
  });

  const { data: keys } = useQuery({
    queryKey: ["keys", projectId],
    queryFn: () => api.listKeys(projectId),
  });

  if (isLoading) {
    return <div className="text-muted-foreground">Loading project...</div>;
  }

  if (!project) {
    return <div className="text-destructive">Project not found</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{project.name}</h1>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="keys">API Keys</TabsTrigger>
          <TabsTrigger value="audit-logs">Audit Logs</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-6">
          <div className="grid gap-4 sm:grid-cols-3">
            <StatCard
              title="Monthly Active Users"
              value={analytics?.mau ?? "-"}
            />
            <StatCard
              title="Active Sessions"
              value={analytics?.active_sessions ?? "-"}
            />
            <StatCard
              title="Total Users"
              value={analytics?.total_users ?? "-"}
            />
          </div>
        </TabsContent>

        <TabsContent value="users" className="mt-6">
          <UserTable projectId={projectId} />
        </TabsContent>

        <TabsContent value="keys" className="mt-6">
          <KeysTab projectId={projectId} keys={keys ?? []} />
        </TabsContent>

        <TabsContent value="audit-logs" className="mt-6">
          <AuditLogTable projectId={projectId} />
        </TabsContent>

        <TabsContent value="settings" className="mt-6">
          <SettingsTab key={project.updated_at} projectId={projectId} project={project} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function KeysTab({
  projectId,
  keys,
}: {
  projectId: string;
  keys: api.ApiKey[];
}) {
  const queryClient = useQueryClient();
  const [rotateDialog, setRotateDialog] = useState<api.ApiKey | null>(null);

  const rotateMutation = useMutation({
    mutationFn: (keyType: string) => api.rotateKey(projectId, keyType),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["keys", projectId] });
      setRotateDialog(null);
      toast.success("Key rotated successfully");
    },
    onError: () => {
      toast.error("Failed to rotate key");
    },
  });

  return (
    <div className="space-y-4">
      <div className="space-y-3">
        {keys.map((key) => (
          <ApiKeyDisplay
            key={key.id}
            apiKey={key}
            showRotate
            onRotate={() => setRotateDialog(key)}
          />
        ))}
      </div>

      <Dialog
        open={!!rotateDialog}
        onOpenChange={() => setRotateDialog(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate API Key</DialogTitle>
            <DialogDescription>
              This will invalidate the current{" "}
              {rotateDialog?.key_type.replace("_", " ")} key and generate a
              new one. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRotateDialog(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={rotateMutation.isPending}
              onClick={() =>
                rotateDialog &&
                rotateMutation.mutate(rotateDialog.key_type)
              }
            >
              {rotateMutation.isPending ? "Rotating..." : "Rotate Key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function SettingsTab({
  projectId,
  project,
}: {
  projectId: string;
  project: api.Project;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(project.name);
  const [config, setConfig] = useState<api.ProjectConfig>(project.config);

  const updateMutation = useMutation({
    mutationFn: () => api.updateProject(projectId, name, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project", projectId] });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      toast.success("Settings saved");
    },
    onError: (err) => {
      toast.error(
        err instanceof api.ApiError ? err.description : "Failed to save"
      );
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    updateMutation.mutate();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Project Settings</CardTitle>
        <CardDescription>
          Configure authentication behavior for this project.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="project-name">Project Name</Label>
            <Input
              id="project-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="email-method">
                Email Verification Method
              </Label>
              <select
                id="email-method"
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
                value={config.email_verification_method}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    email_verification_method: e.target.value,
                  })
                }
              >
                <option value="code">Code</option>
                <option value="link">Link</option>
              </select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="email-ttl">
                Verification TTL (seconds)
              </Label>
              <Input
                id="email-ttl"
                type="number"
                value={config.email_verification_ttl}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    email_verification_ttl: parseInt(e.target.value) || 0,
                  })
                }
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pw-min">Password Min Length</Label>
              <Input
                id="pw-min"
                type="number"
                value={config.password_min_length}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    password_min_length: parseInt(e.target.value) || 0,
                  })
                }
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pw-max">Password Max Length</Label>
              <Input
                id="pw-max"
                type="number"
                value={config.password_max_length}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    password_max_length: parseInt(e.target.value) || 0,
                  })
                }
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="idle-timeout">
                Session Idle Timeout (seconds)
              </Label>
              <Input
                id="idle-timeout"
                type="number"
                value={config.session_idle_timeout}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    session_idle_timeout: parseInt(e.target.value) || 0,
                  })
                }
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="abs-timeout">
                Session Absolute Timeout (seconds)
              </Label>
              <Input
                id="abs-timeout"
                type="number"
                value={config.session_abs_timeout}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    session_abs_timeout: parseInt(e.target.value) || 0,
                  })
                }
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              id="mfa"
              type="checkbox"
              className="h-4 w-4 rounded border-input"
              checked={config.mfa_enabled}
              onChange={(e) =>
                setConfig({ ...config, mfa_enabled: e.target.checked })
              }
            />
            <Label htmlFor="mfa">Enable MFA</Label>
          </div>

          <Button
            type="submit"
            disabled={updateMutation.isPending}
          >
            {updateMutation.isPending ? "Saving..." : "Save Settings"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
