import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({
  createClient: vi.fn(),
}));

vi.mock("@1password/sdk", () => ({ createClient: sdk.createClient }));

describe("1Password SDK client rotation", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-08-26T00:00:00Z"));
    sdk.createClient.mockReset();

    let generation = 0;
    sdk.createClient.mockImplementation(async () => {
      const value = ++generation === 1 ? "old-synthetic" : "new-synthetic";
      return {
        secrets: { resolve: vi.fn(async () => value) },
        vaults: { list: vi.fn(async () => []) },
      };
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("recreates a busy client at the absolute 20-second boundary", async () => {
    const { resolveSecret } = await import("./onepassword-service");

    await expect(resolveSecret("synthetic-token", "op://v/i/f")).resolves.toBe(
      "old-synthetic",
    );

    vi.advanceTimersByTime(19_999);
    await expect(resolveSecret("synthetic-token", "op://v/i/f")).resolves.toBe(
      "old-synthetic",
    );
    expect(sdk.createClient).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(1);
    await expect(resolveSecret("synthetic-token", "op://v/i/f")).resolves.toBe(
      "new-synthetic",
    );
    expect(sdk.createClient).toHaveBeenCalledTimes(2);
  });
});
