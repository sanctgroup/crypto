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
  pgpDecryptMessageVerified,
} from "../wasm/sanct_wasm.js";

export type PgpImportFailureReason =
  | "smartcard_stub"
  | "public_only"
  | "bad_passphrase"
  | "parse"
  | "encryption"
  | "decryption"
  | "generation"
  | "export"
  | "unsafe_key"
  | "verification"
  | "resource_limit";

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
    case "unsafe_key":
    case "verification":
    case "resource_limit":
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

let _initialization: Promise<void> | undefined;

export function initCrypto(
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
): Promise<void> {
  return (_initialization ??= init(input === undefined ? undefined : { module_or_path: input })
    .then(() => undefined)
    .catch((error: unknown) => {
      _initialization = undefined;
      throw error;
    }));
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type EncodableBytes = Uint8Array & {
  toBase64?: () => string;
  toHex?: () => string;
};
const byteDecoders = Uint8Array as typeof Uint8Array & {
  fromBase64?: (value: string) => Uint8Array;
  fromHex?: (value: string) => Uint8Array;
};
const hexPairs = Array.from({ length: 256 }, (_, value) => value.toString(16).padStart(2, "0"));

export function textToBytes(text: string): Uint8Array {
  return encoder.encode(text);
}

export function bytesToText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function bytesToBase64(bytes: Uint8Array): string {
  const native = (bytes as EncodableBytes).toBase64;
  if (native) return native.call(bytes);
  const chunks: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 0x8000)));
  }
  return btoa(chunks.join(""));
}

export function base64ToBytes(base64: string): Uint8Array {
  if (byteDecoders.fromBase64) return byteDecoders.fromBase64(base64);
  const binStr = atob(base64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  const native = (bytes as EncodableBytes).toHex;
  if (native) return native.call(bytes);
  const pairs = new Array<string>(bytes.length);
  for (let i = 0; i < bytes.length; i++) pairs[i] = hexPairs[bytes[i]!]!;
  return pairs.join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) {
    throw new TypeError("Hex input must contain an even number of hexadecimal digits");
  }
  if (byteDecoders.fromHex) return byteDecoders.fromHex(hex);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
