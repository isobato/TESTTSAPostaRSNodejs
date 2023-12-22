const asn1 = require("asn1.js");
const crypto = require("crypto");
const axios = require("axios");

// Define ASN.1 structure for TimeStampReq
const TimeStampReq = asn1.define("TimeStampReq", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("messageImprint")
      .seq()
      .obj(this.key("hashAlgorithm").use(AlgorithmIdentifier), this.key("hashedMessage").octstr()),
    this.key("nonce").optional().int(),
    this.key("certReq").optional().bool(),
    this.key("extensions").optional().seqof(Extension)
  );
});

const AlgorithmIdentifier = asn1.define("AlgorithmIdentifier", function () {
  this.seq().obj(this.key("algorithm").objid(), this.key("parameters").optional().any());
});

const Extension = asn1.define("Extension", function () {
  this.seq().obj(this.key("extnID").objid(), this.key("critical").optional().bool(), this.key("extnValue").octstr());
});

// Function to create and encode TimeStampReq
async function createAndSendTimestampRequest(data, tsaServerUrl) {
  try {
    // Create the hash of the data
    const hash = crypto.createHash("sha256").update(data).digest();

    // Create TimeStampReq object
    const timeStampReqObj = TimeStampReq.encode(
      {
        version: 1,
        messageImprint: {
          hashAlgorithm: { algorithm: [2, 16, 840, 1, 101, 3, 4, 2, 1] }, // OID for sha256
          hashedMessage: hash,
        },
        nonce: Math.floor(Math.random() * 1e9),
        certReq: true,
      },
      "der"
    );

    // Send the request to TSA
    const response = await axios.post(tsaServerUrl, timeStampReqObj, {
      headers: { "Content-Type": "application/timestamp-query" },
      responseType: "arraybuffer",
    });

    // Process the response
    if (response.status === 200) {
      console.log("Timestamp token received.");
      // Further processing of response...
    } else {
      console.log("HTTP request failed with status code:", response.status);
    }
  } catch (error) {
    console.error("Error creating or sending timestamp request:", error);
  }
}

const tsaServerUrl = "http://test-tsa.ca.posta.rs/timestamp"; // Change to the desired TSA URL
createAndSendTimestampRequest(Buffer.from("Test Data"), tsaServerUrl);
