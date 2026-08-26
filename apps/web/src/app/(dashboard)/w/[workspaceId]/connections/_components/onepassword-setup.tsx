"use client";

import { AlertCircle, RefreshCw } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import { Badge } from "@onecli/ui/components/badge";
import { Skeleton } from "@onecli/ui/components/skeleton";
import {
  useVaultStatus,
  type OnePasswordStatusData,
} from "@/hooks/use-vault-status";

export const OnePasswordSetup = () => {
  const { status, loading, isPaired, isReady, fetchStatus } =
    useVaultStatus<OnePasswordStatusData>("onepassword");

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-36" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-9 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (isPaired) {
    const lastError = status?.status_data?.last_error ?? null;
    const hasError = !!lastError;

    return (
      <div className="space-y-6">
        {/* Connection status */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Connection</CardTitle>
              <Badge
                variant="outline"
                className={
                  hasError
                    ? "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400"
                    : "border-brand/20 bg-brand/5 text-brand dark:border-brand/30 dark:bg-brand/10"
                }
              >
                <span
                  className={`mr-1.5 inline-block size-1.5 rounded-full ${hasError ? "bg-red-500" : "bg-brand"}`}
                />
                {hasError ? "Error" : isReady ? "Connected" : "Paired"}
              </Badge>
            </div>
            <CardDescription>
              Pick 1Password as the value source when adding a secret to resolve
              its value on-demand. Secret values and the 1Password bootstrap
              credential are not stored in OneCLI&apos;s database.
            </CardDescription>
          </CardHeader>
          {hasError && (
            <CardContent>
              <div className="bg-destructive/10 text-destructive flex items-start gap-2 rounded-md border border-red-200 p-3 text-sm dark:border-red-900">
                <AlertCircle className="mt-0.5 size-4 shrink-0" />
                <div className="grid gap-1.5">
                  <span>{lastError}</span>
                  <button
                    type="button"
                    onClick={fetchStatus}
                    className="text-muted-foreground hover:text-foreground flex w-fit items-center gap-1 text-xs underline-offset-2 hover:underline"
                  >
                    <RefreshCw className="size-3" />
                    Refresh status
                  </button>
                </div>
              </div>
            </CardContent>
          )}
        </Card>

        {/* Operator-managed runtime identity */}
        <Card>
          <CardHeader>
            <CardTitle>Operator managed</CardTitle>
            <CardDescription>
              The service-account identity is mounted at runtime. To rotate or
              remove it, update the protected broker-host file and restart the
              gateway. The dashboard never receives or stores that token.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  // The broker owns the service-account identity. It is never pasted here.
  return (
    <Card>
      <CardHeader>
        <CardTitle>1Password is not configured</CardTitle>
        <CardDescription>
          The broker operator must mount a read-only 1Password service-account
          token and restart the gateway. This screen intentionally cannot accept
          a token, so OneCLI cannot persist it in the database or backups.
        </CardDescription>
      </CardHeader>
    </Card>
  );
};
