use serde_json::Value;

pub(super) struct Claims {
    pub(super) name: Option<String>,
    pub(super) oid: Option<String>,
}

pub(super) fn claims_from_token(token: &str) -> Claims {
    let payload = token
        .split('.')
        .nth(1)
        .and_then(base64_url_decode)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let claim = |keys: &[&str]| {
        let payload = payload.as_ref()?;
        keys.iter().find_map(|key| payload.get(*key).and_then(Value::as_str)).map(str::to_string)
    };
    Claims { name: claim(&["upn", "unique_name", "preferred_username", "name"]), oid: claim(&["oid"]) }
}

pub(super) fn base64_url_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_are_read_from_the_access_token() {
        let claims = claims_from_token("x.eyJ1cG4iOiAiYUBiLmMiLCAib2lkIjogIm9pZC0xIn0.y");
        assert_eq!(claims.name.as_deref(), Some("a@b.c"));
        assert_eq!(claims.oid.as_deref(), Some("oid-1"));
        assert!(claims_from_token("not-a-jwt").name.is_none());
    }
}
