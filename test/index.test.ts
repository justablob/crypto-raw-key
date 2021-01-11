import "mocha";
import { assert } from "chai";

import * as crypto from "crypto";
import crk from "../src";

describe("crypto-raw-key", () => {
  it("should export and import ed25519 keys", () => {
    let firstKey = crypto.generateKeyPairSync("ed25519");
    let firstKeyPublic = firstKey.publicKey;
    let firstKeyPrivate = firstKey.privateKey;

    let data = crypto.randomBytes(1024);

    let firstSignature = crypto.sign(undefined, data, firstKeyPrivate);

    let exportedKeyPublic = crk.exportKey(firstKeyPublic);
    let exportedKeyPrivate = crk.exportKey(firstKeyPrivate);

    let importedKeyPublic = crk.importKey("ed25519", "public", exportedKeyPublic);
    let importedKeyPrivate = crk.importKey("ed25519", "private", exportedKeyPrivate);

    let firstVerify = crypto.verify(undefined, data, importedKeyPublic, firstSignature);

    let importedSignature = crypto.sign(undefined, data, importedKeyPrivate);

    let importedVerify = crypto.verify(undefined, data, firstKeyPublic, importedSignature);

    assert.equal(Buffer.compare(firstSignature, importedSignature), 0);
    assert(firstVerify,);
    assert(importedVerify);
  });

  it("should export and import ed448 keys", () => {
    let firstKey = crypto.generateKeyPairSync("ed448");
    let firstKeyPublic = firstKey.publicKey;
    let firstKeyPrivate = firstKey.privateKey;

    let data = crypto.randomBytes(1024);

    let firstSignature = crypto.sign(undefined, data, firstKeyPrivate);

    let exportedKeyPublic = crk.exportKey(firstKeyPublic);
    let exportedKeyPrivate = crk.exportKey(firstKeyPrivate);

    let importedKeyPublic = crk.importKey("ed448", "public", exportedKeyPublic);
    let importedKeyPrivate = crk.importKey("ed448", "private", exportedKeyPrivate);

    let firstVerify = crypto.verify(undefined, data, importedKeyPublic, firstSignature);

    let importedSignature = crypto.sign(undefined, data, importedKeyPrivate);

    let importedVerify = crypto.verify(undefined, data, firstKeyPublic, importedSignature);

    assert.equal(Buffer.compare(firstSignature, importedSignature), 0);
    assert(firstVerify,);
    assert(importedVerify);
  });

it("should export and import x25519 keys", () => {
    let helperKey = crypto.generateKeyPairSync("x25519");
    let helperKeyPublic = helperKey.publicKey;
    let helperKeyPrivate = helperKey.privateKey;

    let firstKey = crypto.generateKeyPairSync("x25519");
    let firstKeyPublic = firstKey.publicKey;
    let firstKeyPrivate = firstKey.privateKey;

    let firstSecretFP = crypto.diffieHellman({ privateKey: firstKeyPrivate, publicKey: helperKeyPublic });
    let firstSecretTP = crypto.diffieHellman({ publicKey: firstKeyPublic, privateKey: helperKeyPrivate });

    let exportedKeyPublic = crk.exportKey(firstKeyPublic);
    let exportedKeyPrivate = crk.exportKey(firstKeyPrivate);

    let importedKeyPublic = crk.importKey("x25519", "public", exportedKeyPublic);
    let importedKeyPrivate = crk.importKey("x25519", "private", exportedKeyPrivate);

    let importedSecretFP = crypto.diffieHellman({ privateKey: importedKeyPrivate, publicKey: helperKeyPublic });
    let importedSecretTP = crypto.diffieHellman({ publicKey: importedKeyPublic, privateKey: helperKeyPrivate });

    assert.equal(Buffer.compare(firstSecretFP, importedSecretFP), 0);
    assert.equal(Buffer.compare(firstSecretTP, importedSecretTP), 0);

    assert.equal(Buffer.compare(firstSecretFP, importedSecretTP), 0);
    assert.equal(Buffer.compare(firstSecretTP, importedSecretFP), 0);
  });

it("should export and import x448 keys", () => {
    let helperKey = crypto.generateKeyPairSync("x448");
    let helperKeyPublic = helperKey.publicKey;
    let helperKeyPrivate = helperKey.privateKey;

    let firstKey = crypto.generateKeyPairSync("x448");
    let firstKeyPublic = firstKey.publicKey;
    let firstKeyPrivate = firstKey.privateKey;

    let firstSecretFP = crypto.diffieHellman({ privateKey: firstKeyPrivate, publicKey: helperKeyPublic });
    let firstSecretTP = crypto.diffieHellman({ publicKey: firstKeyPublic, privateKey: helperKeyPrivate });

    let exportedKeyPublic = crk.exportKey(firstKeyPublic);
    let exportedKeyPrivate = crk.exportKey(firstKeyPrivate);

    let importedKeyPublic = crk.importKey("x448", "public", exportedKeyPublic);
    let importedKeyPrivate = crk.importKey("x448", "private", exportedKeyPrivate);


    let importedSecretFP = crypto.diffieHellman({ privateKey: importedKeyPrivate, publicKey: helperKeyPublic });
    let importedSecretTP = crypto.diffieHellman({ publicKey: importedKeyPublic, privateKey: helperKeyPrivate });

    assert.equal(Buffer.compare(firstSecretFP, importedSecretFP), 0);
    assert.equal(Buffer.compare(firstSecretTP, importedSecretTP), 0);

    assert.equal(Buffer.compare(firstSecretFP, importedSecretTP), 0);
    assert.equal(Buffer.compare(firstSecretTP, importedSecretFP), 0);
  });
});