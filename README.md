# OpenEntropyd
A secure protocol for obtaining entropy over the internet.

### Background & Overview
Most modern, cryptographic ciphers rely heavily on the ability to generate strong random numbers in order to ensure the security and integrity of the cipher. Unfortunately, some devices, such as embedded systems, have trouble finding sources of true randomness that produce a significant amount of entropy. In theory and in practice, having a weak random number generator can lead to the decryption of ciphertext, prediction of randomly-generated passwords on the device, and much more.

Openentropyd serves as a solution to the aforementioned issue by serving up blocks of random data that can be queried by authorized users who then add the randomness to their local pool. This is done by a service installed on the client that monitors the available amount of entropy and makes a request when it drops below a threshold.

### Usage
### Architecture

### Potential Issues & Mitigations

1. Poisoning the entropy pool of other computers
2. Eavesdropping on queries to predict the internal state of a querying machine
3. Denial-of-service attacks on the server's entropy pool by rogue users
