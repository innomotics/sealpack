# Security Policy

The sealpack community takes the security of its code seriously. If you
think you have found a security vulnerability, please read the next sections
and follow the instructions to report your finding.

## Security Context

Open source software can be used in various contexts that may go far beyond
what it was originally designed and also secured for. Therefore, we describe
here how sealpack is currently expected to be used in security-sensitive
scenarios.

Being a central tooling for securing data, ensuring the [CIA triand] (https://www.geeksforgeeks.org/the-cia-triad-in-cryptography/)
throughout the whole process is crucial for its operation. 
With multiple security mechanisms combined, any insecurity in the interfaces could potentially lead to a breach of the
confidentiality of parts or all of the artifacts created with sealpack.
Although a full breach of the encryption and the signing mechanism is unlikely, also partial breaches are potentially
harmful to the code and its artifacts.

## Reporting a Vulnerability

Please DO NOT report any potential security vulnerability via a public channel
(mailing list, github issue etc.). Instead, contact the maintainers 
mathias.haimerl@siemens.com and lukas.rabener@siemens.com via email
directly. Please provide a detailed description of the issue, the steps to
reproduce it, the affected versions and, if already available, a proposal for a
fix. You should receive a response within 5 working days. If the issue is
confirmed as a vulnerability by us, we will open a Security Advisory on github
and give credits for your report if desired. This project follows a 90 day
disclosure timeline.