# threshold_signature



## Overview

ComingChat is a privacy social software that supports the signal protocol at the bottom. Substrate supports sr25519 and Schnower's multi-signature, but does not support threshold signatures. The purpose of this project is to provide a threshold signature wallet for the substrate blockchain that supports the sr25519 protocol. Implementation categories include:

- End-to-end private encrypted group chat based on ComingChat, which serves as the basis of private communication for each distributed node with threshold signatures.
- Implement the MAST protocol of BTC taproot in the form of a module on Substrate, which is used to combine the multisig logic of sr25519 to implement threshold signatures based on aggregate signatures.

For details, please refer to [w3f/grant](https://github.com/coming-chat/Grants-Program/blob/master/applications/threshold_signature.md).

