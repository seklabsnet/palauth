"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { isAuthenticated, checkSetupDone } from "@/lib/api";

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    if (isAuthenticated()) {
      router.replace("/projects");
      return;
    }

    checkSetupDone().then((done) => {
      router.replace(done ? "/login" : "/setup");
    });
  }, [router]);

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="text-muted-foreground">Loading...</div>
    </div>
  );
}
