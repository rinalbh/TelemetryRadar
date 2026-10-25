# Public TLS regression captures

These small fixtures come from the official Wireshark source tree, tag
`wireshark-4.4.0`, licensed under GPL-2.0-or-later:

- `tls13-rfc8446.pcap`: `test/captures/tls13-rfc8446.pcap`
- `tls13-rfc8446.keys`: `test/keys/tls13-rfc8446.keys`
- `tls12-dsb.pcapng`: `test/captures/tls12-dsb.pcapng`

Source: https://github.com/wireshark/wireshark/tree/wireshark-4.4.0/test
License: https://github.com/wireshark/wireshark/blob/wireshark-4.4.0/COPYING
The upstream license text is included in `COPYING` alongside these fixtures.

The keys are public test secrets and have no relationship to user captures.
The offline tests demonstrate TLS 1.2/1.3 decryption using only an output pcapng
after the separate key log has been deleted.

`capture-ca.pem` is this project's public certificate test fixture, not a
Wireshark fixture. It contains no private key.
