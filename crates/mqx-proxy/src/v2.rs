use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{ProxyAddresses, ProxyError, ProxyInfo, ProxyOptions, ProxyTls, c_string};

const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const FIXED_LEN: usize = 16;
pub(super) const MAX_FRAMED_LEN: usize = FIXED_LEN + 500;
const UNIX_PATH_LEN: usize = 108;

#[derive(Clone, Copy)]
enum Family {
    Unspecified,
    Ipv4,
    Ipv6,
    Unix,
}

pub(super) fn framed_len(preamble: &[u8]) -> usize {
    FIXED_LEN + usize::from(u16::from_be_bytes([preamble[14], preamble[15]]))
}

pub(super) fn parse(
    input: &[u8],
    options: ProxyOptions,
) -> Result<Option<(ProxyInfo, &[u8])>, ProxyError> {
    // Mosquitto src/proxy_v2.c:proxy_v2__read checks the command and
    // family together. LOCAL with a concrete family takes the PROXY path.
    let Some(preamble) = input.first_chunk::<FIXED_LEN>() else {
        return Ok(None);
    };
    let cmd = preamble[12] & 0x0f;
    if !preamble.starts_with(SIGNATURE) || preamble[12] >> 4 != 2 || cmd > 1 {
        return Err(ProxyError::MalformedHeader);
    }
    let (family, min_len, tlv_offset) = match preamble[13] {
        0x00 if cmd == 0 => (Family::Unspecified, 0, 0),
        0x11 => (Family::Ipv4, 12, 12),
        0x21 => (Family::Ipv6, 36, 36),
        // Mosquitto accepts a non-empty UNIX body and starts scanning for
        // TLVs at 109, not after the standard two 108-byte paths.
        0x31 => (Family::Unix, 1, UNIX_PATH_LEN + 1),
        _ => return Err(ProxyError::MalformedHeader),
    };
    let end = framed_len(preamble);
    if end < FIXED_LEN + min_len {
        return Err(ProxyError::MalformedHeader);
    }
    if !matches!(family, Family::Unspecified) && end > MAX_FRAMED_LEN {
        return Err(ProxyError::TooLong);
    }
    let Some((frame, leftover)) = input.split_at_checked(end) else {
        return Ok(None);
    };
    if matches!(family, Family::Unspecified) {
        // src/proxy_v2.c:proxy_v2__read returns MOSQ_ERR_PROXY;
        // src/loop.c:do_disconnect silently closes this health check.
        return Ok(Some((ProxyInfo::Local, leftover)));
    }
    let body = &frame[FIXED_LEN..];
    let mut tls = Tls::default();
    let mut tlvs = &body[tlv_offset.min(body.len())..];
    while !tlvs.is_empty() {
        // Mosquitto src/proxy_v2.c:read_tlv skips every type except SSL,
        // including CRC32C. The enclosing TLV still has to be well framed.
        let (kind, value) = take_tlv(&mut tlvs)?;
        if kind == 0x20 {
            tls.read_ssl(value, options.use_identity_as_username)?;
        }
    }
    if options.require_tls && !tls.present {
        return Err(ProxyError::TlsRequired);
    }
    if options.require_certificate && !tls.certificate_verified {
        return Err(ProxyError::CertificateRequired);
    }
    Ok(Some((
        ProxyInfo::Proxied {
            addresses: addresses(family, body),
            tls: tls.owned(),
        },
        leftover,
    )))
}

/// The addresses of a complete PROXY v2 frame whose TLVs were rejected.
/// Mosquitto src/proxy_v2.c:proxy_v2__read sets the context address before
/// read_tlv, so its rejection notices name the proxied source.
pub(super) fn rejected_addresses(input: &[u8]) -> Option<ProxyAddresses> {
    let preamble = input.first_chunk::<FIXED_LEN>()?;
    let family = match preamble[13] {
        0x11 => Family::Ipv4,
        0x21 => Family::Ipv6,
        0x31 => Family::Unix,
        _ => return None,
    };
    let frame = input.get(..framed_len(preamble))?;
    Some(addresses(family, &frame[FIXED_LEN..]))
}

fn addresses(family: Family, body: &[u8]) -> ProxyAddresses {
    match family {
        Family::Ipv4 => ProxyAddresses::Ip {
            source: SocketAddr::from((
                Ipv4Addr::new(body[0], body[1], body[2], body[3]),
                port(body, 8),
            )),
            destination: SocketAddr::from((
                Ipv4Addr::new(body[4], body[5], body[6], body[7]),
                port(body, 10),
            )),
        },
        Family::Ipv6 => ProxyAddresses::Ip {
            source: SocketAddr::from((ipv6(&body[..16]), port(body, 32))),
            destination: SocketAddr::from((ipv6(&body[16..32]), port(body, 34))),
        },
        Family::Unix => {
            let (source, remaining) = body.split_at(body.len().min(UNIX_PATH_LEN));
            let destination = &remaining[..remaining.len().min(UNIX_PATH_LEN)];
            ProxyAddresses::Unix {
                source: c_string(source).into(),
                destination: c_string(destination).into(),
            }
        }
        Family::Unspecified => unreachable!(),
    }
}

fn port(body: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([body[offset], body[offset + 1]])
}

fn ipv6(bytes: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())
}

fn take_tlv<'a>(bytes: &mut &'a [u8]) -> Result<(u8, &'a [u8]), ProxyError> {
    let Some(([kind, hi, lo], remaining)) = bytes.split_first_chunk() else {
        return Err(ProxyError::MalformedTlv);
    };
    let Some((value, tail)) =
        remaining.split_at_checked(usize::from(u16::from_be_bytes([*hi, *lo])))
    else {
        return Err(ProxyError::MalformedTlv);
    };
    *bytes = tail;
    Ok((*kind, value))
}

#[derive(Default)]
struct Tls<'a> {
    present: bool,
    certificate_verified: bool,
    version: Option<&'a str>,
    cipher: Option<&'a str>,
    common_name: Option<&'a str>,
}

impl<'a> Tls<'a> {
    fn read_ssl(&mut self, value: &'a [u8], use_identity: bool) -> Result<(), ProxyError> {
        let Some(([client, a, b, c, d], mut bytes)) = value.split_first_chunk() else {
            return Err(ProxyError::MalformedTlv);
        };
        // Mosquitto src/proxy_v2.c:read_tlv_ssl accumulates successful
        // verification across SSL TLVs. CERT_CONN alone is not enough.
        self.certificate_verified |= client & 0x05 == 0x05 && [*a, *b, *c, *d] == [0; 4];
        while !bytes.is_empty() {
            // The C reader bounds each child by the full frame, but if one
            // crosses the SSL TLV its u16 remaining length underflows and
            // it can never reach zero before running out of frame bytes.
            let (kind, data) = take_tlv(&mut bytes)?;
            let field = match kind {
                0x21 => &mut self.version,
                0x23 => &mut self.cipher,
                0x22 if use_identity => {
                    if self.common_name.is_some() {
                        return Err(ProxyError::DuplicateCommonName);
                    }
                    &mut self.common_name
                }
                _ => continue,
            };
            *field = Some(
                mqx_codec::validate_utf8(data)
                    .map_err(|source| ProxyError::InvalidTlsString { kind, source })?,
            );
        }
        // Mosquitto treats any parsed SSL TLV as TLS for require_tls.
        self.present = true;
        Ok(())
    }

    fn owned(self) -> Option<ProxyTls> {
        self.present.then(|| ProxyTls {
            certificate_verified: self.certificate_verified,
            version: self.version.map(str::to_owned),
            cipher: self.cipher.map(str::to_owned),
            common_name: self.common_name.map(str::to_owned),
        })
    }
}
