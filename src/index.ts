import * as crypto from "crypto";

type Algorithms = "ed25519" | "x25519" | "ed448" | "x448";
type Types = "private" | "public";

const asn1: { [x in Algorithms]: { [x in Types]: [number, Buffer, Buffer] } } = {
  ed25519: { // done
    public: [32, Buffer.from("302A300506032B6570032100", "hex"), Buffer.from("", "hex")],
    private: [32, Buffer.from("302E020100300506032B657004220420", "hex"), Buffer.from("", "hex")],
  },
  x25519: {
    public: [32, Buffer.from("302A300506032B656E032100", "hex"), Buffer.from("", "hex")],
    private: [32, Buffer.from("302E020100300506032B656E04220420", "hex"), Buffer.from("", "hex")],
  },
  ed448: { // done
    public: [57, Buffer.from("3043300506032B6571033A00", "hex"), Buffer.from("00", "hex")],
    private: [57, Buffer.from("3047020100300506032B6571043B0439", "hex"), Buffer.from("", "hex")],
  },
  x448: { // done
    public: [56, Buffer.from("3042300506032B656F033900", "hex"), Buffer.from("", "hex")],
    private: [56, Buffer.from("3046020100300506032B656F043A0438", "hex"), Buffer.from("", "hex")],
  },
};

export function exportKey(key: crypto.KeyObject): Buffer {
  if (
    key.asymmetricKeyType !== "ed25519" &&
    key.asymmetricKeyType !== "ed448" &&
    key.asymmetricKeyType !== "x25519" &&
    key.asymmetricKeyType !== "x448"
  ) return null;

  let exportedKeyObject = key.export({
    format: "der",
    type: key.type === "private" ? "pkcs8" : "spki",
  });

  let [ keylen, prefix ] = asn1[key.asymmetricKeyType][key.type as Types];

  return exportedKeyObject.slice(prefix.length).slice(0, keylen);
}

export function importKey(algo: Algorithms, type: Types, key: Buffer): crypto.KeyObject {
  let [ keylen, prefix, suffix ] = asn1[algo][type];

  if (key.length !== keylen) return null;

  let keyBuffer = Buffer.allocUnsafe(prefix.length + keylen + suffix.length);

  prefix.copy(keyBuffer, 0),
  key.copy(keyBuffer, prefix.length);
  suffix.copy(keyBuffer, prefix.length + keylen);

  let keyObject = crypto[type === "private" ? "createPrivateKey" : "createPublicKey"]({
    key: keyBuffer,
    format: "der",
    asymmetricKeyType: algo,
    type: type === "private" ? "pkcs8" : "spki" as any
  });

  return keyObject;
}

export default {
  exportKey,
  importKey,
}