import * as asn1js from "./asn1js";
import { stringToArrayBuffer, bufferToHexCodes } from "./pvutils";
import Certificate from "./pkijs/Certificate.js";
import AttributeTypeAndValue from "./pkijs/AttributeTypeAndValue.js";
import Extension from "./pkijs/Extension.js";
import RSAPublicKey from "./pkijs/RSAPublicKey.js";
import CertificateChainValidationEngine from "./pkijs/CertificateChainValidationEngine.js";
import CertificateRevocationList from "./pkijs/CertificateRevocationList.js";
import {
  getCrypto,
  getAlgorithmParameters,
  setEngine,
} from "./pkijs/common.js";
//import { formatPEM } from "../../examples/examples_common.js";
import BasicConstraints from "./pkijs/BasicConstraints.js";
import ExtKeyUsage from "./pkijs/ExtKeyUsage.js";
import CertificateTemplate from "./pkijs/CertificateTemplate.js";
import CAVersion from "./pkijs/CAVersion.js";
//<nodewebcryptoossl>
//*********************************************************************************
let certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT
let privateKeyBuffer = new ArrayBuffer(0);
let trustedCertificates = []; // Array of root certificates from "CA Bundle"
const intermadiateCertificates = []; // Array of intermediate certificates
const crls = []; // Array of CRLs for all certificates (trusted + intermediate)

let hashAlg = "SHA-1";
let signAlg = "RSASSA-PKCS1-v1_5";
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

function parseCertificate() {
  //region Initial check
  if (certificateBuffer.byteLength === 0) {
    alert("Nothing to parse!");
    return;
  }
  //endregion

  //region Initial activities
  document.getElementById("cert-extn-div").style.display = "none";

  const issuerTable = document.getElementById("cert-issuer-table");
  while (issuerTable.rows.length > 1)
    issuerTable.deleteRow(issuerTable.rows.length - 1);

  const subjectTable = document.getElementById("cert-subject-table");
  while (subjectTable.rows.length > 1)
    subjectTable.deleteRow(subjectTable.rows.length - 1);

  const extensionTable = document.getElementById("cert-extn-table");
  while (extensionTable.rows.length > 1)
    extensionTable.deleteRow(extensionTable.rows.length - 1);
  //endregion

  //region Decode existing X.509 certificate
  const asn1 = asn1js.fromBER(certificateBuffer);
  const certificate = new Certificate({ schema: asn1.result });
  //endregion

  //region Put information about X.509 certificate issuer
  const rdnmap = {
    "2.5.4.6": "C",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.3": "CN",
    "2.5.4.7": "L",
    "2.5.4.8": "S",
    "2.5.4.12": "T",
    "2.5.4.42": "GN",
    "2.5.4.43": "I",
    "2.5.4.4": "SN",
    "1.2.840.113549.1.9.1": "E-mail",
  };

  for (const typeAndValue of certificate.issuer.typesAndValues) {
    let typeval = rdnmap[typeAndValue.type];
    if (typeof typeval === "undefined") typeval = typeAndValue.type;

    const subjval = typeAndValue.value.valueBlock.value;

    const row = issuerTable.insertRow(issuerTable.rows.length);
    const cell0 = row.insertCell(0);
    // noinspection InnerHTMLJS
    cell0.innerHTML = typeval;
    const cell1 = row.insertCell(1);
    // noinspection InnerHTMLJS
    cell1.innerHTML = subjval;
  }
  //endregion

  //region Put information about X.509 certificate subject
  for (const typeAndValue of certificate.subject.typesAndValues) {
    let typeval = rdnmap[typeAndValue.type];
    if (typeof typeval === "undefined") typeval = typeAndValue.type;

    const subjval = typeAndValue.value.valueBlock.value;

    const row = subjectTable.insertRow(subjectTable.rows.length);
    const cell0 = row.insertCell(0);
    // noinspection InnerHTMLJS
    cell0.innerHTML = typeval;
    const cell1 = row.insertCell(1);
    // noinspection InnerHTMLJS
    cell1.innerHTML = subjval;
  }
  //endregion

  //region Put information about X.509 certificate serial number
  // noinspection InnerHTMLJS
  document.getElementById("cert-serial-number").innerHTML = bufferToHexCodes(
    certificate.serialNumber.valueBlock.valueHex
  );
  //endregion

  //region Put information about issuance date
  // noinspection InnerHTMLJS
  document.getElementById(
    "cert-not-before"
  ).innerHTML = certificate.notBefore.value.toString();
  //endregion

  //region Put information about expiration date
  // noinspection InnerHTMLJS
  document.getElementById(
    "cert-not-after"
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
  }

  // noinspection InnerHTMLJS
  document.getElementById("cert-keysize").innerHTML = publicKeySize;
  //endregion

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

  let signatureAlgorithm = algomap[certificate.signatureAlgorithm.algorithmId];
  if (typeof signatureAlgorithm === "undefined")
    signatureAlgorithm = certificate.signatureAlgorithm.algorithmId;
  else
    signatureAlgorithm = `${signatureAlgorithm} (${certificate.signatureAlgorithm.algorithmId})`;

  // noinspection InnerHTMLJS
  document.getElementById("cert-sign-algo").innerHTML = signatureAlgorithm;
  //endregion

  //region Put information about certificate extensions
  if ("extensions" in certificate) {
    for (let i = 0; i < certificate.extensions.length; i++) {
      const row = extensionTable.insertRow(extensionTable.rows.length);
      const cell0 = row.insertCell(0);
      // noinspection InnerHTMLJS
      cell0.innerHTML = certificate.extensions[i].extnID;
    }

    document.getElementById("cert-extn-div").style.display = "block";
  }
  //endregion
}
//*********************************************************************************
export function createCertificateInternal() {
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
  certificate.serialNumber = new asn1js.Integer({ value: 1 });
  certificate.issuer.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.6", // Country name
      value: new asn1js.PrintableString({ value: "RU" }),
    })
  );
  certificate.issuer.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.3", // Common name
      value: new asn1js.BmpString({ value: "Test" }),
    })
  );
  certificate.subject.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.6", // Country name
      value: new asn1js.PrintableString({ value: "RU" }),
    })
  );
  certificate.subject.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.3", // Common name
      value: new asn1js.BmpString({ value: "Test" }),
    })
  );

  certificate.notBefore.value = new Date(2019, 1, 1);
  certificate.notAfter.value = new Date(2022, 1, 1);

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
    keyPurposes: [
      "2.5.29.37.0", // anyExtendedKeyUsage
      "1.3.6.1.5.5.7.3.1", // id-kp-serverAuth
      "1.3.6.1.5.5.7.3.2", // id-kp-clientAuth
      "1.3.6.1.5.5.7.3.3", // id-kp-codeSigning
      "1.3.6.1.5.5.7.3.4", // id-kp-emailProtection
      "1.3.6.1.5.5.7.3.8", // id-kp-timeStamping
      "1.3.6.1.5.5.7.3.9", // id-kp-OCSPSigning
      "1.3.6.1.4.1.311.10.3.1", // Microsoft Certificate Trust List signing
      "1.3.6.1.4.1.311.10.3.4", // Microsoft Encrypted File System
    ],
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
export function createCertificate() {
  return createCertificateInternal().then(
    () => {
      const certificateString = String.fromCharCode.apply(
        null,
        new Uint8Array(certificateBuffer)
      );

      let resultString = "-----BEGIN CERTIFICATE-----\r\n";
      resultString = `${resultString}${formatPEM(
        window.btoa(certificateString)
      )}`;
      resultString = `${resultString}\r\n-----END CERTIFICATE-----\r\n`;

      parseCertificate();

      alert("Certificate created successfully!");

      const privateKeyString = String.fromCharCode.apply(
        null,
        new Uint8Array(privateKeyBuffer)
      );

      resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
      resultString = `${resultString}${formatPEM(
        window.btoa(privateKeyString)
      )}`;
      resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;

      // noinspection InnerHTMLJS
      document.getElementById("new_signed_data").innerHTML = resultString;

      alert("Private key exported successfully!");
    },
    (error) => {
      if (error instanceof Object) alert(error.message);
      else alert(error);
    }
  );
}

document
  .getElementById("generate-certificate")
  .addEventListener("click", createCertificate);
