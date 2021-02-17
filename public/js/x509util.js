import * as asn1js from "./asn1js/asn1.js";
import { stringToArrayBuffer, bufferToHexCodes } from "./pvutils/utils.js";
import Certificate from "./pkijs/Certificate.js";
import AttributeTypeAndValue from "./pkijs/AttributeTypeAndValue.js";
import Extension from "./pkijs/Extension.js";
import RSAPublicKey from "./pkijs/RSAPublicKey.js";
import {
  getCrypto,
  getAlgorithmParameters,
  getAlgorithmByOID,
} from "./pkijs/common.js";
import BasicConstraints from "./pkijs/BasicConstraints.js";
import ExtKeyUsage from "./pkijs/ExtKeyUsage.js";
import CertificateTemplate from "./pkijs/CertificateTemplate.js";
import CAVersion from "./pkijs/CAVersion.js";
//<nodewebcryptoossl>
//*********************************************************************************
let certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT
let privateKeyBuffer = new ArrayBuffer(0);
let trustedCertificates = []; // Array of root certificates from "CA Bundle"

let hashAlg = "SHA-1";
let signAlg = "RSASSA-PKCS1-v1_5";

let issuerObject, subjectObject, extensionArray;

//*********************************************************************************
//region Put information about X.509 certificate issuer
const rdnmap = {
  "2.5.4.6": "C",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.3": "CN",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.12": "T",
  "2.5.4.42": "GN",
  "2.5.4.43": "I",
  "2.5.4.4": "SN",
  "1.2.840.113549.1.9.1": "E",
};

//region Put information about signature algorithm
const algomap = {
  "1.2.840.113549.1.1.2": "MD2 with RSA",
  "1.2.840.113549.1.1.4": "MD5 with RSA",
  "1.2.840.10040.4.3": "SHA1 with DSA",
  "1.2.840.10045.4.1": "SHA1 with ECDSA",
  "1.2.840.10045.4.3.2": "SHA256 with ECDSA",
  "1.2.840.10045.4.3.3": "SHA384 with ECDSA",
  "1.2.840.10045.4.3.4": "SHA512 with ECDSA",
  "1.2.840.113549.1.1.10": "RSA-PSS",
  "1.2.840.113549.1.1.5": "SHA1 with RSA",
  "1.2.840.113549.1.1.14": "SHA224 with RSA",
  "1.2.840.113549.1.1.11": "SHA256 with RSA",
  "1.2.840.113549.1.1.12": "SHA384 with RSA",
  "1.2.840.113549.1.1.13": "SHA512 with RSA",
}; // array mapping of common algorithm OIDs and corresponding types

const keyPurposeMap = {
  "2.5.29.37.0": "anyExtendedKeyUsage",
  "1.3.6.1.5.5.7.3.1": "serverAuth",
  "1.3.6.1.5.5.7.3.2": "clientAuth",
  "1.3.6.1.5.5.7.3.3": "codeSigning",
  "1.3.6.1.5.5.7.3.4": "emailProtection",
  "1.3.6.1.5.5.7.3.8": "timeStamping",
  "1.3.6.1.5.5.7.3.9": "OCSPSigning",
  "1.3.6.1.4.1.311.10.3.1": "Microsoft Certificate Trust List signing",
  "1.3.6.1.4.1.311.10.3.4": "Microsoft Encrypted File System",
};

function checkedArray(name) {
  const elems = document.getElementsByName(name);
  let arr = [];
  for (let i = 0; i < elems.length; i++) {
    if (elems[i].checked) {
      arr.push(elems[i].value);
    }
  }
  return arr;
}

//**************************************************************************************
//region Auxilliary functions
//**************************************************************************************
/**
 * Format string in order to have each line with length equal to 64
 * @param {string} pemString String to format
 * @returns {string} Formatted string
 */
function formatPEM(pemString) {
  const PEM_STRING_LENGTH = pemString.length,
    LINE_LENGTH = 64;
  const wrapNeeded = PEM_STRING_LENGTH > LINE_LENGTH;

  if (wrapNeeded) {
    let formattedString = "",
      wrapIndex = 0;

    for (let i = LINE_LENGTH; i < PEM_STRING_LENGTH; i += LINE_LENGTH) {
      formattedString += pemString.substring(wrapIndex, i) + "\r\n";
      wrapIndex = i;
    }

    formattedString += pemString.substring(wrapIndex, PEM_STRING_LENGTH);
    return formattedString;
  } else {
    return pemString;
  }
}
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
//*********************************************************************************

function parseCertificate() {
  //region Initial check
  if (certificateBuffer.byteLength === 0) {
    alert("Nothing to parse!");
    return;
  }
  //endregion

  //region Initial activities
  const issuerTable = document.getElementById("issuer");
  issuerTable.innerHTML = "";

  const subjectTable = document.getElementById("subject");
  subjectTable.innerHTML = "";

  const extensionTable = document.getElementById("x509v3-extensions");
  extensionTable.innerHTML = "";
  //endregion

  //region Decode existing X.509 certificate
  const asn1 = asn1js.fromBER(certificateBuffer);
  const certificate = new Certificate({ schema: asn1.result });
  //endregion

  issuerObject = {};
  for (const typeAndValue of certificate.issuer.typesAndValues) {
    let typeval = rdnmap[typeAndValue.type];
    if (typeof typeval === "undefined") typeval = typeAndValue.type;

    const subjval = typeAndValue.value.valueBlock.value;

    issuerObject[typeval] = subjval;
  }
  issuerTable.innerHTML = JSON.stringify(issuerObject);
  //endregion

  //region Put information about X.509 certificate subject
  subjectObject = {};
  for (const typeAndValue of certificate.subject.typesAndValues) {
    let typeval = rdnmap[typeAndValue.type];
    if (typeof typeval === "undefined") typeval = typeAndValue.type;

    const subjval = typeAndValue.value.valueBlock.value;

    subjectObject[typeval] = subjval;
  }
  subjectTable.innerHTML = JSON.stringify(subjectObject);
  //endregion

  //region Put information about X.509 certificate version
  // noinspection InnerHTMLJS
  document.getElementById("version").innerHTML = certificate.version;

  //region Put information about X.509 certificate serial number
  // noinspection InnerHTMLJS
  document.getElementById("serial-number").innerHTML = bufferToHexCodes(
    certificate.serialNumber.valueBlock.valueHex
  );
  //endregion

  //region Put information about issuance date
  // noinspection InnerHTMLJS
  document.getElementById(
    "validity-not-before"
  ).innerHTML = certificate.notBefore.value.toString();
  //endregion

  //region Put information about expiration date
  // noinspection InnerHTMLJS
  document.getElementById(
    "validity-not-after"
  ).innerHTML = certificate.notAfter.value.toString();
  //endregion

  //region Put information about subject public key size
  let publicKeySize = "< unknown >";

  if (
    certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf(
      "1.2.840.113549"
    ) !== -1
  ) {
    const asn1PublicKey = asn1js.fromBER(
      certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex
    );
    const rsaPublicKey = new RSAPublicKey({ schema: asn1PublicKey.result });

    const modulusView = new Uint8Array(
      rsaPublicKey.modulus.valueBlock.valueHex
    );
    let modulusBitLength = 0;

    if (modulusView[0] === 0x00)
      modulusBitLength =
        (rsaPublicKey.modulus.valueBlock.valueHex.byteLength - 1) * 8;
    else
      modulusBitLength =
        rsaPublicKey.modulus.valueBlock.valueHex.byteLength * 8;

    publicKeySize = modulusBitLength.toString();
  } else {
    // ECDSA
    publicKeySize = getAlgorithmByOID(
      certificate.subjectPublicKeyInfo.parsedKey.namedCurve
    ).name;
  }

  // noinspection InnerHTMLJS
  document.getElementById("public-key-size").innerHTML = publicKeySize;
  //endregion

  let signatureAlgorithm = algomap[certificate.signatureAlgorithm.algorithmId];
  if (typeof signatureAlgorithm === "undefined")
    signatureAlgorithm = certificate.signatureAlgorithm.algorithmId;
  else
    signatureAlgorithm = `${signatureAlgorithm} (${certificate.signatureAlgorithm.algorithmId})`;

  // noinspection InnerHTMLJS
  document.getElementById(
    "public-key-algorithm"
  ).innerHTML = signatureAlgorithm;
  //endregion

  //region Put information about certificate extensions
  extensionArray = Array();
  if ("extensions" in certificate) {
    for (let i = 0; i < certificate.extensions.length; i++) {
      extensionArray.push(certificate.extensions[i].extnID);

      // extkeyUsage
      if (certificate.extensions[i].extnID === "2.5.29.37") {
        const transkeyusage = certificate.extensions[
          i
        ].parsedValue.keyPurposes.map((i) => keyPurposeMap[i] || i);
        document.getElementById("ext-key-usage").innerHTML = transkeyusage.join(
          " / "
        );
      }
    }

    document.getElementById(
      "x509v3-extensions"
    ).innerHTML = extensionArray.join(" / ");
  }
  document.getElementById("dump-cert").innerHTML = JSON.stringify(
    certificate,
    null,
    4
  );
  //endregion
}
//*********************************************************************************
function createCertificateInternal() {
  //region Initial variables
  let sequence = Promise.resolve();

  const certificate = new Certificate();

  let publicKey;
  let privateKey;

  trustedCertificates = [];
  //endregion

  //region Get a "crypto" extension
  const crypto = getCrypto();
  if (typeof crypto === "undefined")
    return Promise.reject("No WebCrypto extension found");
  //endregion

  //region Put a static values
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({
    value: Math.floor(Math.random() * 999999999),
  });

  // root cert subject(static)
  certificate.issuer.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.6", // Country name
      value: new asn1js.BmpString({ value: "JP" }),
    })
  );
  certificate.issuer.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.3", // Common name
      value: new asn1js.BmpString({ value: "WebX509 Root" }),
    })
  );

  // cert subject setup
  const subjectList = document.getElementById("input-subject").value.split("/");
  subjectList.every((subj) => {
    const subjkv = subj.split("=", 2);
    if (subjkv.length != 2) return true;
    const k = Object.keys(rdnmap).find((rdnk) => {
      return rdnmap[rdnk] === subjkv[0];
    });
    if (k) {
      certificate.subject.typesAndValues.push(
        new AttributeTypeAndValue({
          type: k,
          value: new asn1js.BmpString({ value: subjkv[1] }),
        })
      );
    }
    return true;
  });

  const now = new Date();
  certificate.notBefore.value = now;

  let notAfter = new Date();
  notAfter = notAfter.setDate(
    now.getDate() + Number(document.getElementById("input-expiry").value)
  );
  certificate.notAfter.value = new Date(notAfter);

  certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array

  //region "BasicConstraints" extension
  const basicConstr = new BasicConstraints({
    cA: true,
    pathLenConstraint: 3,
  });

  certificate.extensions.push(
    new Extension({
      extnID: "2.5.29.19",
      critical: true,
      extnValue: basicConstr.toSchema().toBER(false),
      parsedValue: basicConstr, // Parsed value for well-known extensions
    })
  );
  //endregion

  //region "KeyUsage" extension
  const bitArray = new ArrayBuffer(1);
  const bitView = new Uint8Array(bitArray);

  bitView[0] |= 0x02; // Key usage "cRLSign" flag
  bitView[0] |= 0x04; // Key usage "keyCertSign" flag

  const keyUsage = new asn1js.BitString({ valueHex: bitArray });

  certificate.extensions.push(
    new Extension({
      extnID: "2.5.29.15",
      critical: false,
      extnValue: keyUsage.toBER(false),
      parsedValue: keyUsage, // Parsed value for well-known extensions
    })
  );
  //endregion

  //region "ExtendedKeyUsage" extension
  const extKeyUsage = new ExtKeyUsage({
    keyPurposes: checkedArray("extkeyusage"),
  });

  certificate.extensions.push(
    new Extension({
      extnID: "2.5.29.37",
      critical: false,
      extnValue: extKeyUsage.toSchema().toBER(false),
      parsedValue: extKeyUsage, // Parsed value for well-known extensions
    })
  );
  //endregion

  //region Microsoft-specific extensions
  const certType = new asn1js.Utf8String({ value: "certType" });

  certificate.extensions.push(
    new Extension({
      extnID: "1.3.6.1.4.1.311.20.2",
      critical: false,
      extnValue: certType.toBER(false),
      parsedValue: certType, // Parsed value for well-known extensions
    })
  );

  const prevHash = new asn1js.OctetString({
    valueHex: new Uint8Array([
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
    ]).buffer,
  });

  certificate.extensions.push(
    new Extension({
      extnID: "1.3.6.1.4.1.311.21.2",
      critical: false,
      extnValue: prevHash.toBER(false),
      parsedValue: prevHash, // Parsed value for well-known extensions
    })
  );

  const certificateTemplate = new CertificateTemplate({
    templateID: "1.1.1.1.1.1",
    templateMajorVersion: 10,
    templateMinorVersion: 20,
  });

  certificate.extensions.push(
    new Extension({
      extnID: "1.3.6.1.4.1.311.21.7",
      critical: false,
      extnValue: certificateTemplate.toSchema().toBER(false),
      parsedValue: certificateTemplate, // Parsed value for well-known extensions
    })
  );

  const caVersion = new CAVersion({
    certificateIndex: 10,
    keyIndex: 20,
  });

  certificate.extensions.push(
    new Extension({
      extnID: "1.3.6.1.4.1.311.21.1",
      critical: false,
      extnValue: caVersion.toSchema().toBER(false),
      parsedValue: caVersion, // Parsed value for well-known extensions
    })
  );
  //endregion
  //endregion

  //region Create a new key pair
  sequence = sequence.then(() => {
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

    return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
  });
  //endregion

  //region Store new key in an interim variables
  sequence = sequence.then(
    (keyPair) => {
      publicKey = keyPair.publicKey;
      privateKey = keyPair.privateKey;
    },
    (error) => Promise.reject(`Error during key generation: ${error}`)
  );
  //endregion

  //region Exporting public key into "subjectPublicKeyInfo" value of certificate
  sequence = sequence.then(() =>
    certificate.subjectPublicKeyInfo.importKey(publicKey)
  );
  //endregion

  //region Signing final certificate
  sequence = sequence.then(
    () => certificate.sign(privateKey, hashAlg),
    (error) => Promise.reject(`Error during exporting public key: ${error}`)
  );
  //endregion

  //region Encode and store certificate
  sequence = sequence.then(
    () => {
      trustedCertificates.push(certificate);
      certificateBuffer = certificate.toSchema(true).toBER(false);
    },
    (error) => Promise.reject(`Error during signing: ${error}`)
  );
  //endregion

  //region Exporting private key
  sequence = sequence.then(() => crypto.exportKey("pkcs8", privateKey));
  //endregion

  //region Store exported key on Web page
  sequence = sequence.then(
    (result) => {
      privateKeyBuffer = result;
    },
    (error) => Promise.reject(`Error during exporting of private key: ${error}`)
  );
  //endregion

  return sequence;
}
//*********************************************************************************
function createCertificate() {
  const processing = document.getElementById("gen-processing").style;
  processing.display = "inline-block";
  return createCertificateInternal().then(
    () => {
      const certificateString = String.fromCharCode.apply(
        null,
        new Uint8Array(certificateBuffer)
      );

      let resultCertString = "-----BEGIN CERTIFICATE-----\r\n";
      resultCertString = `${resultCertString}${formatPEM(
        window.btoa(certificateString)
      )}`;
      resultCertString = `${resultCertString}\r\n-----END CERTIFICATE-----\r\n`;
      document.getElementById("gen-cert").innerHTML = resultCertString;

      parseCertificate();

      const privateKeyString = String.fromCharCode.apply(
        null,
        new Uint8Array(privateKeyBuffer)
      );

      let resultPrivString = `-----BEGIN PRIVATE KEY-----\r\n`;
      resultPrivString = `${resultPrivString}${formatPEM(
        window.btoa(privateKeyString)
      )}`;
      resultPrivString = `${resultPrivString}\r\n-----END PRIVATE KEY-----\r\n`;

      // noinspection InnerHTMLJS
      document.getElementById("gen-priv").innerHTML = resultPrivString;
      processing.display = "none";
    },
    (error) => {
      processing.display = "none";
      if (error instanceof Object) alert(error.message);
      else alert(error);
    }
  );
}
//*********************************************************************************
function inspectCertificate() {
  let cert = String(document.getElementById("inspect-cert").value)
    .trim()
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\r?\n/g, "");
  certificateBuffer = stringToArrayBuffer(window.atob(cert));
  parseCertificate();
}

function copyText(target) {
  target.select();
  document.execCommand("copy");
  document.getSelection().empty(target);
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
document.getElementById("cert-copy").addEventListener("click", () => {
  copyText(document.querySelector("#gen-cert"));
});

document
  .getElementById("generate-operation")
  .addEventListener("click", createCertificate);

document.getElementById("inspect-operation").addEventListener("click", () => {
  inspectCertificate();
});
