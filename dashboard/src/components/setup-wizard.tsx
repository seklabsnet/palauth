"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
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
import { ApiKeyDisplay } from "@/components/api-key-display";
import * as api from "@/lib/api";
import { toast } from "sonner";

const STEPS = [
  "Create Admin Account",
  "Create Project",
  "API Keys",
  "Get Started",
];

export function SetupWizard() {
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [checking, setChecking] = useState(true);

  // Step 0: Admin
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Redirect to login if setup is already done.
  useEffect(() => {
    api.checkSetupDone().then((done) => {
      if (done) {
        router.replace("/login");
      } else {
        setChecking(false);
      }
    });
  }, [router]);

  // Step 1: Project
  const [projectName, setProjectName] = useState("");
  const [createdProject, setCreatedProject] =
    useState<api.CreateProjectResponse | null>(null);

  async function handleCreateAdmin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await api.adminSetup(email, password);
      setPassword("");
      toast.success("Admin account created");
      setStep(1);
    } catch (err) {
      setError(
        err instanceof api.ApiError ? err.description : "Setup failed"
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleCreateProject(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const result = await api.createProject(projectName);
      setCreatedProject(result);
      toast.success("Project created");
      setStep(2);
    } catch (err) {
      setError(
        err instanceof api.ApiError ? err.description : "Project creation failed"
      );
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 p-4">
      <div className="w-full max-w-lg">
        {/* Progress */}
        <div className="mb-8 flex items-center justify-center gap-2">
          {STEPS.map((s, i) => (
            <div key={s} className="flex items-center gap-2">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full text-sm font-medium ${
                  i <= step
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted text-muted-foreground"
                }`}
              >
                {i + 1}
              </div>
              {i < STEPS.length - 1 && (
                <div
                  className={`h-0.5 w-8 ${
                    i < step ? "bg-primary" : "bg-muted"
                  }`}
                />
              )}
            </div>
          ))}
        </div>

        {/* Step 0: Admin Account */}
        {step === 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Create Admin Account</CardTitle>
              <CardDescription>
                Set up the initial administrator account for PalAuth.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreateAdmin} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="admin@example.com"
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Minimum 15 characters"
                    required
                    minLength={15}
                  />
                </div>
                {error && (
                  <p className="text-sm text-destructive">{error}</p>
                )}
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? "Creating..." : "Create Admin"}
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Step 1: Create Project */}
        {step === 1 && (
          <Card>
            <CardHeader>
              <CardTitle>Create Your First Project</CardTitle>
              <CardDescription>
                Projects isolate users, API keys, and configuration.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreateProject} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="project-name">Project Name</Label>
                  <Input
                    id="project-name"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    placeholder="My App"
                    required
                  />
                </div>
                {error && (
                  <p className="text-sm text-destructive">{error}</p>
                )}
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? "Creating..." : "Create Project"}
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Step 2: API Keys */}
        {step === 2 && createdProject && (
          <Card>
            <CardHeader>
              <CardTitle>Your API Keys</CardTitle>
              <CardDescription>
                Save these keys securely. Secret keys are only shown once.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {createdProject.api_keys.map((key) => (
                <ApiKeyDisplay key={key.id} apiKey={key} />
              ))}
              <Button className="w-full" onClick={() => setStep(3)}>
                Continue
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Step 3: Quickstart */}
        {step === 3 && (
          <Card>
            <CardHeader>
              <CardTitle>You are all set!</CardTitle>
              <CardDescription>
                PalAuth is ready to use. Here is a quick overview.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-lg border bg-muted/50 p-4 text-sm space-y-2">
                <p>
                  <strong>1.</strong> Use the publishable key in your frontend
                  SDK to initialize PalAuth.
                </p>
                <p>
                  <strong>2.</strong> Use the secret key in your backend to
                  verify tokens and manage users.
                </p>
                <p>
                  <strong>3.</strong> Configure email verification, MFA, and
                  session policies in the project settings.
                </p>
              </div>
              <Button
                className="w-full"
                onClick={() => router.push("/projects")}
              >
                Go to Dashboard
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
