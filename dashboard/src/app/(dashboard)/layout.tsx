"use client";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/lib/auth-context";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const { isAuthenticated, logout } = useAuth();

  useEffect(() => {
    if (!isAuthenticated) {
      router.replace("/login");
    }
  }, [isAuthenticated, router]);

  if (!isAuthenticated) {
    return null;
  }

  const navItems = [
    { href: "/projects", label: "Projects" },
  ];

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="flex w-56 flex-col border-r bg-muted/30">
        <div className="p-4">
          <h1 className="text-lg font-semibold">PalAuth</h1>
        </div>
        <Separator />
        <nav className="flex-1 p-2 space-y-1">
          {navItems.map((item) => (
            <Link key={item.href} href={item.href}>
              <Button
                variant={pathname.startsWith(item.href) ? "secondary" : "ghost"}
                className="w-full justify-start"
              >
                {item.label}
              </Button>
            </Link>
          ))}
        </nav>
        <Separator />
        <div className="p-2">
          <Button
            variant="ghost"
            className="w-full justify-start text-muted-foreground"
            onClick={logout}
          >
            Sign Out
          </Button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <div className="p-6">{children}</div>
      </main>
    </div>
  );
}
