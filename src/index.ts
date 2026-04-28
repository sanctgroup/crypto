import init from "../wasm/sanct_wasm.js";

export {
  type IdentityKeys,
  type PrivateKeys,
  type RecoveryResult,
  type PgpGeneratedKey,
  type PgpImportedKey,
  type PgpPublicKeyInfo,
  type PgpDecryptResult,
  generateSalt,
  deriveMasterKey,
  generateIdentityKeys,
  decryptPrivateKeys,
  encryptMessage,
  decryptMessage,
  sealForRecipient,
  sealMetadataForRecipient,
  encryptDraft,
  encryptMetadata,
  decryptMetadata,
  computeSubjectHash,
  generateRecoveryPhrase,
  recoveryKeyFromPhrase,
  hashRecoveryKey,
  encryptBundleForRecovery,
  decryptBundleWithRecovery,
  pgpGenerateKey,
  pgpImportKey,
  pgpExportKey,
  pgpKeyInfo,
  pgpEncryptToRecipients,
  pgpDecryptMessage,
} from "../wasm/sanct_wasm.js";

export type PgpImportFailureReason =
  | "smartcard_stub"
  | "public_only"
  | "bad_passphrase"
  | "parse"
  | "encryption"
  | "decryption"
  | "generation"
  | "export";

export function classifyPgpError(message: string): PgpImportFailureReason | "unknown" {
  const code = message.split(":", 1)[0]?.trim();
  switch (code) {
    case "smartcard_stub":
    case "public_only":
    case "bad_passphrase":
    case "parse":
    case "encryption":
    case "decryption":
    case "generation":
    case "export":
      return code;
    default:
      return "unknown";
  }
}

export interface UnlockedKeys {
  readonly x25519Secret: Uint8Array;
  readonly mlkem768Secret: Uint8Array;
  readonly threadingKey: Uint8Array;
}

let _initialized = false;

export async function initCrypto(
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
): Promise<void> {
  if (_initialized) return;
  await init(input);
  _initialized = true;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function textToBytes(text: string): Uint8Array {
  return encoder.encode(text);
}

export function bytesToText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function bytesToBase64(bytes: Uint8Array): string {
  const binStr = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binStr);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binStr = atob(base64);
  return Uint8Array.from(binStr, (c) => c.charCodeAt(0));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
