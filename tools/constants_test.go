package tools_test

// Using default softHSM configuration. Change it if necessary.
const p11Lib = "/lib/softhsm/libsofthsm2.so" // Path used by Debian
const p11Key = "1234"
const p11LabelRSA = "test-hsm-rsa"
const p11LabelECDSA = "test-hsm-ecdsa"
