"use client";

import Link from "next/link";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { Project } from "@/lib/api";

interface ProjectCardProps {
  project: Project;
}

export function ProjectCard({ project }: ProjectCardProps) {
  return (
    <Link href={`/projects/${project.id}`}>
      <Card className="transition-colors hover:border-primary/50 cursor-pointer">
        <CardHeader>
          <CardTitle className="text-lg">{project.name}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-sm text-muted-foreground">
            Created {new Date(project.created_at).toLocaleDateString()}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
