use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{ProxyAddresses, ProxyError, ProxyInfo, c_string};

const MAX_LEN: usize = 108;

pub(super) fn parse(input: &[u8]) -> Result<Option<(ProxyInfo, &[u8])>, ProxyError> {
    // Mosquitto src/proxy_v1.c:proxy_v1__read includes CRLF in its limit
    // and first checks for it upon receiving the third byte.
    let prefix = &input[..input.len().min(MAX_LEN)];
    let Some(end) = prefix.windows(2).skip(1).position(|pair| pair == b"\r\n") else {
        return if prefix.len() == MAX_LEN {
            Err(ProxyError::TooLong)
        } else {
            Ok(None)
        };
    };
    let end = end + 1;
    Ok(Some((decode(&prefix[..end])?, &input[end + 2..])))
}

fn decode(line: &[u8]) -> Result<ProxyInfo, ProxyError> {
    // Mosquitto src/proxy_v1.c:proxy_v1__decode requires the space even
    // after UNKNOWN, then ignores anything after that signature.
    if line.starts_with(b"PROXY UNKNOWN ") {
        return Ok(ProxyInfo::Unknown);
    }
    let (ipv6, fields) = if let Some(fields) = line.strip_prefix(b"PROXY TCP4 ") {
        (false, fields)
    } else if let Some(fields) = line.strip_prefix(b"PROXY TCP6 ") {
        (true, fields)
    } else {
        return Err(ProxyError::MalformedHeader);
    };

    let mut fields = c_string(fields);
    let source = take_field(&mut fields).ok_or(ProxyError::MalformedHeader)?;
    let destination = take_field(&mut fields).ok_or(ProxyError::MalformedHeader)?;
    let source_port = take_field(&mut fields).ok_or(ProxyError::MalformedHeader)?;
    let destination_port = take_field(&mut fields).ok_or(ProxyError::MalformedHeader)?;
    if !fields.is_empty() {
        return Err(ProxyError::MalformedHeader);
    }

    let source_port = parse_port(source_port).ok_or(ProxyError::MalformedHeader)?;
    let destination_port = parse_port(destination_port).ok_or(ProxyError::MalformedHeader)?;
    let parse_ip = |field| {
        let text = std::str::from_utf8(field).ok()?;
        if ipv6 {
            text.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
        } else {
            text.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
        }
    };
    let source_text = std::str::from_utf8(source).ok().map(Box::from);
    let source = parse_ip(source).ok_or(ProxyError::MalformedHeader)?;
    let destination = parse_ip(destination).ok_or(ProxyError::MalformedHeader)?;
    Ok(ProxyInfo::Proxied {
        addresses: ProxyAddresses::Ip {
            source: SocketAddr::new(source, source_port),
            destination: SocketAddr::new(destination, destination_port),
            source_text,
        },
        tls: None,
    })
}

fn take_field<'a>(fields: &mut &'a [u8]) -> Option<&'a [u8]> {
    // Mosquitto src/proxy_v1.c:proxy_v1__decode checks strtok_r's saveptr
    // after four tokens. One trailing space is consumed; two are rejected.
    let start = fields.iter().position(|&byte| byte != b' ')?;
    let text = &fields[start..];
    if let Some(end) = text.iter().position(|&byte| byte == b' ') {
        *fields = &text[end + 1..];
        Some(&text[..end])
    } else {
        *fields = &[];
        Some(text)
    }
}

fn parse_port(field: &[u8]) -> Option<u16> {
    // Mosquitto src/proxy_v1.c:proxy_v1__decode checks the result of atoi,
    // not the token. Match Linux's 64-bit strtol followed by narrowing to int.
    let start = field
        .iter()
        .position(|&byte| !matches!(byte, b'\t'..=b'\r' | b' '))?;
    let (negative, digits) = match &field[start..] {
        [b'-', remaining @ ..] => (true, remaining),
        [b'+', remaining @ ..] => (false, remaining),
        remaining => (false, remaining),
    };
    let mut value = 0_i64;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            break;
        }
        let digit = i64::from(byte - b'0');
        value = value.saturating_mul(10);
        value = if negative {
            value.saturating_sub(digit)
        } else {
            value.saturating_add(digit)
        };
    }
    let port = u16::try_from(value as i32).ok()?;
    (port != 0).then_some(port)
}
