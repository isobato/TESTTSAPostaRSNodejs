# Test TSA Server "Posta Rs"
This project contains tests (example) for the TSA Server "Posta Rs".

## Prerequisites
Before you begin, ensure you have met the following requirements:

Note: The necessary root CA certificate can be found
Test TSA (Time-Stamping Authority) https://test-tsa.ca.posta.rs/index.html

## TEST2018CA1-Novo
Based on the provided decoded JSON content of the "TEST 2018 CA 1 - Novo" certificate, we can draw the following conclusions:

1. Intermediate Certificate: This is indeed an intermediate certificate. The basicConstraints extension is set to "CA:TRUE, pathlen:0", indicating it's a CA (Certificate Authority) certificate with a path length constraint, typical for intermediate certificates. Additionally, the issuer is different from the subject, showing it's issued by another entity (in this case, "TEST 2018 CA Root - Novo").

2. Revocation Checking Support:
    - CRL Distribution Points: The certificate contains crlDistributionPoints specifying URLs where the CRL can be obtained. These URLs are:
        - ldap://ldap-ocsp.ca.posta.rs/CN=TEST%202018%20CA%20Root%20-%20Novo,...?certificateRevocationList;binary
        - http://repository.ca.posta.rs/crl/TEST2018CARoot-Novo.crl
    - OCSP Information: The authorityInfoAccess extension includes information for CA Issuers, which is useful for retrieving the issuer's certificate but does not directly provide an OCSP server URL for this particular certificate.

Given this information, we can check the revocation status of this intermediate certificate using the provided CRL URLs. The absence of a direct OCSP URL in the authorityInfoAccess extension suggests that OCSP might not be the primary method for revocation checking for this certificate, or that OCSP checking would need to be performed using a different approach, such as querying the issuer's OCSP server directly if known.