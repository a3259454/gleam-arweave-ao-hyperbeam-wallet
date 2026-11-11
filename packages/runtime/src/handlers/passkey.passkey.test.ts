import { describe, expect, it, vi } from "vitest";
import { bytesToBase64Url, type StoragePort } from "@gleam/core";
import { userErrorMessage } from "@gleam/core/src/models/user-errors.ts";
import { PasskeyHandler, type PasskeyVault } from "./passkey";

function createFakeStorage(): StoragePort & { store: Map<string, unknown> } {
  const store = new Map<string, unknown>();
  return {
    store,
    async get<T>(key: string) {
      return store.has(key) ? (store.get(key) as T) : null;
    },
    async set<T>(key: string, value: T) {
      store.set(key, value);
    },
    async setMany(entries: Record<string, unknown>) {
      for (const [key, value] of Object.entries(entries)) store.set(key, value);
    },
    async remove(key: string) {
      store.delete(key);
    },
    watch() {
      return () => {};
    },
  };
}

const PASSWORD = "correct horse battery staple";
const PRF = bytesToBase64Url(new Uint8Array(32).fill(3));
const OTHER_PRF = bytesToBase64Url(new Uint8Array(32).fill(4));

function fakeVault(overrides: Partial<PasskeyVault> = {}): PasskeyVault {
  return {
    checkVaultPassword: vi.fn(async ({ password }: { password: string }) => {
      if (password !== PASSWORD) throw new Error("That password didn't work.");
    }),
    unlockWallet: vi.fn(async ({ password }: { password: string }) => {
      if (password !== PASSWORD) throw new Error("That password didn't work.");
      return { unlockedWalletIds: ["wallet-1"] };
    }),
    hasVaultPassword: vi.fn(async () => true),
    ...overrides,
  };
}

const ENROLL = { password: PASSWORD, credentialId: "cred-1", prfSalt: "salt", prfOutput: PRF };

describe("PasskeyHandler", () => {
  it("reports no passkey until one is enrolled", async () => {
    const handler = new PasskeyHandler(createFakeStorage(), fakeVault());
    expect(await handler.getPasskeyStatus()).toEqual({ enrolled: false });
  });

  it("enrolls, then exposes only the public ceremony inputs", async () => {
    const storage = createFakeStorage();
    const handler = new PasskeyHandler(storage, fakeVault());
    await handler.enrollPasskey(ENROLL);

    const status = await handler.getPasskeyStatus();
    expect(status).toMatchObject({ enrolled: true, credentialId: "cred-1", prfSalt: "salt" });
    expect(JSON.stringify(status)).not.toContain("ciphertext");
    expect(JSON.stringify([...storage.store.values()])).not.toContain(PASSWORD);
  });

  it("refuses to enroll with a password that doesn't open the vault", async () => {
    const storage = createFakeStorage();
    const handler = new PasskeyHandler(storage, fakeVault());
    await expect(handler.enrollPasskey({ ...ENROLL, password: "nope" })).rejects.toThrow(/didn't work/);
    expect(storage.store.size).toBe(0);
  });

  it("unlocks with the enrolled passkey's PRF output", async () => {
    const vault = fakeVault();
    const handler = new PasskeyHandler(createFakeStorage(), vault);
    await handler.enrollPasskey(ENROLL);

    await expect(handler.unlockWithPasskey({ credentialId: "cred-1", prfOutput: PRF })).resolves.toEqual({
      unlockedWalletIds: ["wallet-1"],
    });
    expect(vault.unlockWallet).toHaveBeenCalledWith({ password: PASSWORD });
  });

  it("refuses another credential or a wrong PRF output", async () => {
    const handler = new PasskeyHandler(createFakeStorage(), fakeVault());
    await handler.enrollPasskey(ENROLL);

    await expect(handler.unlockWithPasskey({ credentialId: "cred-2", prfOutput: PRF })).rejects.toThrow(/isn't the passkey/);
    await expect(handler.unlockWithPasskey({ credentialId: "cred-1", prfOutput: OTHER_PRF })).rejects.toThrow(
      /didn't unlock/,
    );
  });

  it("drops a passkey whose password no longer opens the vault", async () => {
    const vault = fakeVault();
    const handler = new PasskeyHandler(createFakeStorage(), vault);
    await handler.enrollPasskey(ENROLL);
    vi.mocked(vault.unlockWallet).mockRejectedValueOnce(new Error(userErrorMessage("passwordFailed")));

    await expect(handler.unlockWithPasskey({ credentialId: "cred-1", prfOutput: PRF })).rejects.toThrow(/no longer matches/);
    expect(await handler.getPasskeyStatus()).toEqual({ enrolled: false });
  });

  it("keeps the passkey when the vault fails for a reason other than the password", async () => {
    const vault = fakeVault();
    const handler = new PasskeyHandler(createFakeStorage(), vault);
    await handler.enrollPasskey(ENROLL);
    vi.mocked(vault.unlockWallet).mockRejectedValueOnce(new Error("Gleam couldn't run its password check on this device."));

    await expect(handler.unlockWithPasskey({ credentialId: "cred-1", prfOutput: PRF })).rejects.toThrow(/password check/);
    expect(await handler.getPasskeyStatus()).toMatchObject({ enrolled: true });
  });

  it("forgets the passkey once the vault has no password", async () => {
    const vault = fakeVault();
    const storage = createFakeStorage();
    const handler = new PasskeyHandler(storage, vault);
    await handler.enrollPasskey(ENROLL);
    vi.mocked(vault.hasVaultPassword).mockResolvedValue(false);

    expect(await handler.getPasskeyStatus()).toEqual({ enrolled: false });
    expect(storage.store.has("local:passkey")).toBe(false);
  });

  it("removes the passkey", async () => {
    const handler = new PasskeyHandler(createFakeStorage(), fakeVault());
    await handler.enrollPasskey(ENROLL);
    await handler.removePasskey();
    expect(await handler.getPasskeyStatus()).toEqual({ enrolled: false });
  });
});
