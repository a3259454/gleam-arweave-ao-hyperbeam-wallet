import {
  base64UrlToBytes,
  unwrapWithPasskey,
  wrapWithPasskey,
  type PasskeyEnrollment,
  type PasskeyStatus,
  type StoragePort,
} from "@gleam/core";
import { userErrorMessage } from "@gleam/core/src/models/user-errors.ts";

const PASSKEY_KEY = "local:passkey";

/** The vault operations a passkey stands in for. `WalletLifecycleHandler` provides them. */
export interface PasskeyVault {
  checkVaultPassword(req: { password: string }): Promise<void>;
  unlockWallet(req: { password: string }): Promise<{ unlockedWalletIds: string[] }>;
  hasVaultPassword(): Promise<boolean>;
}

function isEnrollment(value: unknown): value is PasskeyEnrollment {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    candidate.version === 1 &&
    typeof candidate.credentialId === "string" &&
    candidate.credentialId.length > 0 &&
    typeof candidate.prfSalt === "string" &&
    typeof candidate.iv === "string" &&
    typeof candidate.ciphertext === "string" &&
    typeof candidate.createdAt === "number"
  );
}

function decodePrfOutput(value: string): Uint8Array<ArrayBuffer> {
  try {
    return base64UrlToBytes(value);
  } catch {
    throw new Error(userErrorMessage("passkeyUnexpectedSecret"));
  }
}

/**
 * Passkey unlock. The passkey never replaces the password: it wraps it.
 * Unlocking unwraps the password with the passkey's PRF output and runs
 * the ordinary password unlock, so every wallet, the auto-lock timer and
 * the key session behave exactly as after typing the password.
 */
export class PasskeyHandler {
  constructor(
    private readonly storage: StoragePort,
    private readonly vault: PasskeyVault,
  ) {}

  /**
   * An enrollment outlives the vault password it wraps when the last
   * keyfile wallet is removed, so it is dropped here rather than offered.
   */
  private async loadEnrollment(): Promise<PasskeyEnrollment | null> {
    const raw = await this.storage.get<unknown>(PASSKEY_KEY);
    if (!isEnrollment(raw)) return null;
    if (!(await this.vault.hasVaultPassword())) {
      await this.removePasskey();
      return null;
    }
    return raw;
  }

  async getPasskeyStatus(): Promise<PasskeyStatus> {
    const enrollment = await this.loadEnrollment();
    if (!enrollment) return { enrolled: false };
    return {
      enrolled: true,
      credentialId: enrollment.credentialId,
      prfSalt: enrollment.prfSalt,
      createdAt: enrollment.createdAt,
    };
  }

  async enrollPasskey(req: {
    password: string;
    credentialId: string;
    prfSalt: string;
    prfOutput: string;
  }): Promise<void> {
    await this.vault.checkVaultPassword({ password: req.password });
    if (req.credentialId.length === 0 || req.prfSalt.length === 0) {
      throw new Error(userErrorMessage("passkeyBadResponse"));
    }
    const wrapped = await wrapWithPasskey(req.password, decodePrfOutput(req.prfOutput), req.credentialId);
    const enrollment: PasskeyEnrollment = {
      version: 1,
      credentialId: req.credentialId,
      prfSalt: req.prfSalt,
      ...wrapped,
      createdAt: Date.now(),
    };
    await this.storage.set(PASSKEY_KEY, enrollment);
  }

  async unlockWithPasskey(req: { credentialId: string; prfOutput: string }): Promise<{ unlockedWalletIds: string[] }> {
    const enrollment = await this.loadEnrollment();
    if (!enrollment) {
      throw new Error(userErrorMessage("passkeyNotSetUp"));
    }
    if (enrollment.credentialId !== req.credentialId) {
      throw new Error(userErrorMessage("passkeyWrongCredential"));
    }
    const password = await unwrapWithPasskey(enrollment, decodePrfOutput(req.prfOutput), enrollment.credentialId);
    try {
      return await this.vault.unlockWallet({ password });
    } catch (error) {
      // Only a password the vault no longer accepts means the enrollment is
      // stale: every wallet it protected was removed and a new password set.
      // A KDF, storage or keyring fault reaches here too, and deleting the
      // passkey for it would cost the user the convenient way in that only
      // the password can set up again.
      if (!(error instanceof Error && error.message === userErrorMessage("passwordFailed"))) throw error;
      await this.removePasskey();
      throw new Error(userErrorMessage("passkeyStale"));
    }
  }

  async removePasskey(): Promise<void> {
    await this.storage.remove(PASSKEY_KEY);
  }
}
