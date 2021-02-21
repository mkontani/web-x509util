import { copyText, formatPEM } from "./common.js";
import { getAlgorithmParameters } from "./pkijs/common.js";

/*
 * initial variables
 */
let privkeyBuffer = new ArrayBuffer(0);
let pubkeyBuffer = new ArrayBuffer(0);

let hashAlg = "SHA-1";
let signAlg = "RSASSA-PKCS1-v1_5";

//**************************************************************************************
//region Auxilliary functions
//**************************************************************************************
function handleHashAlgOnChange() {
  const hashOption = document.getElementById("hash_alg").value;
  switch (hashOption) {
    case "alg_SHA1":
      hashAlg = "sha-1";
      break;
    case "alg_SHA256":
      hashAlg = "sha-256";
      break;
    case "alg_SHA384":
      hashAlg = "sha-384";
      break;
    case "alg_SHA512":
      hashAlg = "sha-512";
      break;
    default:
  }
}
//*********************************************************************************
function handleSignAlgOnChange() {
  const signOption = document.getElementById("sign_alg").value;
  switch (signOption) {
    case "alg_RSA15":
      signAlg = "RSASSA-PKCS1-V1_5";
      selectableSizeOnChange("rsa");
      break;
    case "alg_RSA2":
      signAlg = "RSA-PSS";
      selectableSizeOnChange("rsa");
      break;
    case "alg_ECDSA":
      signAlg = "ECDSA";
      selectableSizeOnChange("ecdsa");
      break;
    default:
  }
}
//*********************************************************************************
function selectableSizeOnChange(alg) {
  const rsa_elms = document.getElementsByClassName("rsa_size");
  const ecdsa_elms = document.getElementsByClassName("ecdsa_size");
  switch (alg) {
    case "rsa":
      for (let i = 0; i < rsa_elms.length; i++) {
        rsa_elms[i].style.display = "block";
      }
      rsa_elms[0].selected = true;
      for (let i = 0; i < ecdsa_elms.length; i++) {
        ecdsa_elms[i].style.display = "none";
      }
      break;
    case "ecdsa":
      for (let i = 0; i < rsa_elms.length; i++) {
        rsa_elms[i].style.display = "none";
      }
      for (let i = 0; i < ecdsa_elms.length; i++) {
        ecdsa_elms[i].style.display = "block";
      }
      ecdsa_elms[0].selected = true;
      break;
    default:
      break;
  }
}

async function createKeyPair() {
  const processing = document.getElementById("gen-processing").style;
  processing.display = "inline-block";
  //region Get default algorithm parameters for key generation
  const algorithm = getAlgorithmParameters(signAlg, "generatekey");
  if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = hashAlg;
  //endregion

  //overwrite keysize
  const keysize = document.getElementById("key_size").value;
  if (String(keysize).startsWith("P-")) {
    // ECDSA
    algorithm.algorithm.namedCurve = keysize;
  } else {
    // RSA
    algorithm.algorithm.modulusLength = keysize;
  }

  const keyPair = await window.crypto.subtle.generateKey(
    algorithm.algorithm,
    true,
    ["sign", "verify"]
  );
  const privKey = await window.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  );
  const privateKeyString = String.fromCharCode.apply(
    null,
    new Uint8Array(privKey)
  );
  let resultPrivString =
    `-----BEGIN PRIVATE KEY-----\r\n` +
    `${formatPEM(window.btoa(privateKeyString))}` +
    `\r\n-----END PRIVATE KEY-----\r\n`;
  document.getElementById("gen-priv").innerHTML = resultPrivString;

  const pubKey = await window.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );
  const pubKeyString = String.fromCharCode.apply(null, new Uint8Array(pubKey));
  let resultPubString =
    `-----BEGIN PUBLIC KEY-----\r\n` +
    `${formatPEM(window.btoa(pubKeyString))}` +
    `\r\n-----END PUBLIC KEY-----\r\n`;
  document.getElementById("gen-pub").innerHTML = resultPubString;
  processing.display = "none";
}

document.getElementById("hash_alg").addEventListener("change", () => {
  handleHashAlgOnChange();
});
document.getElementById("sign_alg").addEventListener("change", () => {
  handleSignAlgOnChange();
});

document.getElementById("priv-copy").addEventListener("click", () => {
  copyText(document.querySelector("#gen-priv"));
});
document.getElementById("pub-copy").addEventListener("click", () => {
  copyText(document.querySelector("#gen-pub"));
});

document
  .getElementById("generate-operation")
  .addEventListener("click", async () => {
    await createKeyPair();
  });
