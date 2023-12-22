const asn1js = require("asn1js");
const axios = require("axios");
const crypto = require("crypto");
const pkijs = require("pkijs");
const fs = require("fs");
const path = require("path");
const { Certificate } = pkijs;

async function timestampData(data, tsaUrl) {
  // Generate a hash of the data
  const hash = crypto.createHash("sha256").update(data).digest();

  // Create the TimeStampReq ASN.1 structure
  const messageImprint = new pkijs.MessageImprint({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: "2.16.840.1.101.3.4.2.1", // OID for SHA-256
    }),
    hashedMessage: new asn1js.OctetString({ valueHex: hash }),
  });

  const timeStampReq = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: messageImprint,
    nonce: new asn1js.Integer({ value: Math.floor(Math.random() * 1e9) }),
    certReq: true,
  });

  const timeStampReqBuffer = timeStampReq.toSchema(true).toBER(false);

  try {
    // Send the request to the TSA
    const response = await axios.post(tsaUrl, Buffer.from(timeStampReqBuffer), {
      headers: { "Content-Type": "application/timestamp-query" },
      responseType: "arraybuffer",
    });

    // Handle the TSA's response
    if (response.status === 200) {
      console.log("Timestamp received:", response.data);
      const parsedResponse = parseTsaResponse(response.data);
      console.log(JSON.stringify(parsedResponse, null, 4));

      return parsedResponse;
    } else {
      console.error("Failed to get timestamp:", response.status, response.data);
      return null;
    }
  } catch (error) {
    console.error("Error in timestamping data:", error);
    return null;
  }
}

function parseTsaResponse(responseData) {
  const asn1 = asn1js.fromBER(responseData);

  if (asn1.offset === -1) {
    console.error("Error decoding ASN.1 data");
    return null;
  }

  // Log the raw ASN.1 structure for inspection
  console.log(JSON.stringify(asn1.result.toJSON(), null, 4));

  const timeStampResp = new pkijs.TimeStampResp({ schema: asn1.result });

  const timeStampToken = timeStampResp.timeStampToken; // PKCS#7 SignedData object
  const contentInfo = new pkijs.ContentInfo({ schema: timeStampToken.toSchema() });
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  // Extracting information from TimeStampToken
  const encapContentInfo = signedData.encapContentInfo;
  const eContent = encapContentInfo.eContent; // Should contain the actual TSTInfo structure

  // Parse TSTInfo to extract genTime, messageImprint, and serialNumber
  const tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(eContent.valueBlock.valueHex).result });

  // Extract public key from the first certificate in the SignedData (if present)
  let publicKeyInfo = null;
  let tsaCertificate;
  if (signedData.certificates && signedData.certificates.length > 0) {
    const certificate = signedData.certificates[0];
    publicKeyInfo = certificate.subjectPublicKeyInfo;
    tsaCertificate = certificate.toSchema(true).toBER(false);
  }

  return {
    TimeStampToken: timeStampToken.toSchema().toJSON(), // Convert to JSON for demonstration
    messageImprint: tstInfo.messageImprint.toJSON(),
    genTime: tstInfo.genTime.toISOString(),
    serialNumber: tstInfo.serialNumber.valueBlock.toString(),
    publicKey: publicKeyInfo ? publicKeyInfo.toJSON() : null,
    tsaCertificate: tsaCertificate ? Buffer.from(tsaCertificate).toString("base64") : null,
  };
}

async function validateTsaCertificates(tsaCertificate, rootCertPath, intermediateCertPath) {
  // Load and parse the root and intermediate certificates
  const rootCertPem = fs.readFileSync(rootCertPath).toString();
  const intermediateCertPem = fs.readFileSync(intermediateCertPath).toString();

  const rootCertBER = decodePemToBER(rootCertPem);
  const intermediateCertBER = decodePemToBER(intermediateCertPem);

  // Convert base64-encoded TSA certificate to ArrayBuffer/BER
  const tsaCertBER = Buffer.from(tsaCertificate, "base64").buffer;

  // Verify the certificate chain
  const isValid = await validateCertificateChain(tsaCertBER, intermediateCertBER, rootCertBER);

  return isValid; // Boolean indicating whether the TSA's certificate is valid
}

function decodePemToBER(pem) {
  if (typeof pem !== "string") {
    throw new Error("Expected PEM as string");
  }

  // Load certificate in PEM encoding (base64 encoded DER)
  const b64 = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, "");

  // Now that we have decoded the cert it's now in DER-encoding
  const der = Buffer.from(b64, "base64");

  // And massage the cert into a BER encoded one
  return new Uint8Array(der).buffer;
}

async function validateCertificateChain(tsaCertBER, intermediateCertBER, rootCertBER) {
  const rootCert = decodeCert(rootCertBER);
  const intermediateCert = decodeCert(intermediateCertBER);
  const tsaCert = decodeCert(tsaCertBER);

  const crlUrl = getCrlUrlFromCert(intermediateCert);
  const crl1raw = getCrlFromUrl(crlUrl);
  const crl1 = new pkijs.CertificateRevocationList({ schema: crl1raw.result });

  const intermediateCertStatus = checkCertificateStatus(intermediateCert, crl1);
  const tsaCertStatus = checkCertificateStatus(tsaCert, crl1);

  const hasInvalid = [intermediateCertStatus, tsaCertStatus].some((x) => !x.isValid);

  return !hasInvalid; // true if valid, false otherwise
}

function decodeCert(ber) {
  const asn1 = asn1js.fromBER(ber);
  return new Certificate({ schema: asn1.result });
}

function getCrlUrlFromCert(intermediateCert) {
  let crlUrls;
  const crlDistPointsExt = intermediateCert.extensions.find((ext) => ext.extnID === "2.5.29.31");
  if (crlDistPointsExt) {
    const distributionPoints = crlDistPointsExt.parsedValue.distributionPoints;
    const flattenedUrls = distributionPoints.flatMap((dp) => dp.distributionPoint.flatMap((point) => point.value));
    crlUrls = flattenedUrls.filter((url) => url.startsWith("http"));
    console.log(crlUrls); // These are the CRL URLs
  }

  return crlUrls[0];
}

async function getCrlFromUrl(url) {
  // Download the CRL
  const response = await axios.get(url, { responseType: "arraybuffer" });
  const crlArrayBuffer = response.data;

  // Parse the CRL
  return asn1js.fromBER(crlArrayBuffer);
}

function checkCertificateStatus(certificate, crl) {
  try {
    // Check if the certificate is expired
    const currentDate = new Date();
    const notBefore = certificate.notBefore.value;
    const notAfter = certificate.notAfter.value;

    if (currentDate < notBefore || currentDate > notAfter) {
      return { isValid: false, reason: "Certificate is expired" };
    }

    // Check revocation status
    const isRevoked =
      crl.revokedCertificates?.some((revokedCert) => revokedCert.userCertificate.isEqual(certificate.serialNumber)) ||
      false;

    return {
      isValid: !isRevoked,
      reason: isRevoked ? "Certificate is revoked" : "Certificate is valid",
    };
  } catch (error) {
    console.error("Error checking certificate status:", error);
    return { isValid: null, reason: "Error checking certificate status" };
  }
}

// Example usage
const tsaUrl = "http://test-tsa.ca.posta.rs/timestamp"; // Replace with the actual TSA URL
(async () => {
  try {
    const result = await timestampData("Sample data to be timestamped", tsaUrl);

    // Usage example
    const rootCertPath = path.join(__dirname, "TEST2018CARoot-Novo.pem");
    const intermediateCertPath = path.join(__dirname, "TEST2018CA1-Novo.pem");

    const isValid = await validateTsaCertificates(result.tsaCertificate, rootCertPath, intermediateCertPath);
    console.log("Certificate is valid:", isValid);
  } catch (error) {
    console.error("Error:", error);
  }
})();

// async function isCertificateRevoked(certificateSerialNumber, crlUrl) {
//   try {
//     // Download the CRL
//     const response = await axios.get(crlUrl, { responseType: "arraybuffer" });
//     const crlArrayBuffer = response.data;

//     // Parse the CRL
//     const crlAsn1 = asn1js.fromBER(crlArrayBuffer);
//     const crl = new pkijs.CertificateRevocationList({ schema: crlAsn1.result });

//     // Check if the CRL contains revoked certificates
//     if (crl.revokedCertificates) {
//       // Check if the certificate's serial number is in the CRL
//       const isRevoked = crl.revokedCertificates.some((revokedCert) =>
//         revokedCert.userCertificate.isEqual(certificateSerialNumber)
//       );

//       return isRevoked;
//     } else {
//       // No revoked certificates in the CRL
//       return false;
//     }
//   } catch (error) {
//     console.error("Error checking revocation status:", error);
//     return null;
//   }
// }

// // Example usage
// const serialNumber = "44EEE74019DA3A8525"; // Replace with the actual serial number in hex
// const crlUrl = "http://repository.ca.posta.rs/crl/TEST2018CARoot-Novo.crl"; // Replace with the actual CRL URL
// isCertificateRevoked(serialNumber, crlUrl).then((isRevoked) => {
//   if (isRevoked === null) {
//     console.log("Could not determine revocation status");
//   } else if (isRevoked) {
//     console.log("Certificate is revoked");
//   } else {
//     console.log("Certificate is not revoked");
//   }
// });

// // Usage example
// const rootCertPath = path.join(__dirname, "TEST2018CARoot-Novo.pem");
// const intermediateCertPath = path.join(__dirname, "TEST2018CA1-Novo.pem");

// validateTsaCertificates(result.tsaCertificate, rootCertPath, intermediateCertPath)
//   .then((isValid) => console.log("Certificate is valid:", isValid))
//   .catch((error) => console.error("Certificate validation error:", error));

// OLD CODE -------------------------------------------------------

// // Define ASN.1 structure for TimeStampReq
// const TimeStampReq = asn1.define("TimeStampReq", function () {
//   this.seq().obj(
//     this.key("version").int(),
//     this.key("messageImprint")
//       .seq()
//       .obj(this.key("hashAlgorithm").use(AlgorithmIdentifier), this.key("hashedMessage").octstr()),
//     this.key("nonce").optional().int(),
//     this.key("certReq").optional().bool(),
//     this.key("extensions").optional().seqof(Extension)
//   );
// });

// const AlgorithmIdentifier = asn1.define("AlgorithmIdentifier", function () {
//   this.seq().obj(this.key("algorithm").objid(), this.key("parameters").optional().any());
// });

// const Extension = asn1.define("Extension", function () {
//   this.seq().obj(this.key("extnID").objid(), this.key("critical").optional().bool(), this.key("extnValue").octstr());
// });

// // Function to create and encode TimeStampReq
// async function createAndSendTimestampRequest(data, tsaServerUrl, outputFile) {
//   try {
//     // Create the hash of the data
//     const hash = crypto.createHash("sha256").update(data).digest();

//     // Create TimeStampReq object
//     const timeStampReqObj = TimeStampReq.encode(
//       {
//         version: 1,
//         messageImprint: {
//           hashAlgorithm: { algorithm: [2, 16, 840, 1, 101, 3, 4, 2, 1] }, // OID for sha256
//           hashedMessage: hash,
//         },
//         nonce: Math.floor(Math.random() * 1e9),
//         certReq: true,
//       },
//       "der"
//     );

//     // Send the request to TSA
//     const response = await axios.post(tsaServerUrl, timeStampReqObj, {
//       headers: { "Content-Type": "application/timestamp-query" },
//       responseType: "arraybuffer",
//     });

//     // Process the response
//     if (response.status === 200) {
//       console.log("Timestamp token received.");

//       const respBuffer = Buffer.from(response.data);
//       const parsedResponse = parseTimeStampResp(respBuffer);

//       console.log(parsedResponse);

//       // Further processing of response...
//     } else {
//       console.log("HTTP request failed with status code:", response.status);
//     }
//   } catch (error) {
//     console.error("Error creating or sending timestamp request:", error);
//   }
// }

// function parseTimeStampResp(responseBuffer) {
//   // Convert the response (Buffer) to a forge buffer
//   const forgeBuffer = forge.util.createBuffer(responseBuffer.toString("binary"));

//   // Parse the buffer as ASN.1
//   const asn1 = forge.asn1.fromDer(forgeBuffer);

//   // Interpret the ASN.1 structure as TimeStampResp (based on RFC 3161)
//   // Note: This requires understanding of the ASN.1 structure of TimeStampResp
//   const timeStampResp = interpretTimeStampResp(asn1);

//   return timeStampResp;
// }

// function interpretTimeStampResp(asn1) {
//   // Implement the logic to interpret the ASN.1 structure
//   // according to the structure of TimeStampResp defined in RFC 3161
//   // This step is non-trivial and requires understanding of ASN.1 and RFC 3161

//   // Example: Extracting some basic information
//   const status = forge.asn1.derToOid(asn1.value[0].value[0].value);
//   const timeStampToken = asn1.value[1]; // timeStampToken is typically an ASN.1 structure
//   const p7 = forge.pkcs7.messageFromAsn1(timeStampToken);

//   const certificates = p7.certificates;
//   const certificate = certificates && certificates.length > 0 ? certificates[0] : null;

//   // Return interpreted data (simplified example)
//   return {
//     status,
//     timeStampToken, // You might need to further parse this based on its structure
//     certificate,
//   };
// }

// const tsaServerUrl = "http://test-tsa.ca.posta.rs/timestamp"; // Change to the desired TSA URL
// const outputFile = path.join(__dirname, "timestamp_token.tst"); // Output file path
// createAndSendTimestampRequest(Buffer.from("Test Data"), tsaServerUrl, outputFile);
