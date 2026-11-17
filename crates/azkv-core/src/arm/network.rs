use std::net::IpAddr;

use crate::model::VaultInfo;

pub(super) fn client_allowed(info: &VaultInfo, ip: IpAddr) -> bool {
    if info.public_network_access.as_deref().is_some_and(|access| access.eq_ignore_ascii_case("Disabled")) {
        return false;
    }
    match info.firewall.as_deref() {
        Some(action) if action.eq_ignore_ascii_case("Deny") => info.ip_rules.iter().any(|rule| ip_in_rule(ip, rule)),
        Some(action) if action.eq_ignore_ascii_case("Allow") => true,
        // Azure defaults the firewall action to Allow when it is not set.
        None => true,
        _ => false,
    }
}

pub(super) fn ip_in_rule(ip: IpAddr, rule: &str) -> bool {
    let rule = rule.trim();
    let (base, prefix) = match rule.split_once('/') {
        Some((base, prefix)) => match prefix.parse::<u8>() {
            Ok(prefix) => (base, Some(prefix)),
            Err(_) => return false,
        },
        None => (rule, None),
    };
    match (ip, base.trim().parse::<IpAddr>()) {
        (IpAddr::V4(ip), Ok(IpAddr::V4(base))) => {
            let prefix = prefix.unwrap_or(32);
            prefix <= 32 && (prefix == 0 || u32::from(ip) >> (32 - prefix) == u32::from(base) >> (32 - prefix))
        },
        (IpAddr::V6(ip), Ok(IpAddr::V6(base))) => {
            let prefix = prefix.unwrap_or(128);
            prefix <= 128 && (prefix == 0 || u128::from(ip) >> (128 - prefix) == u128::from(base) >> (128 - prefix))
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_rules_match_single_addresses_and_cidrs() {
        assert!(ip_in_rule("51.103.78.171".parse().unwrap(), "51.103.78.171"));
        assert!(ip_in_rule("51.103.78.171".parse().unwrap(), "51.103.78.0/24"));
        assert!(!ip_in_rule("51.103.79.1".parse().unwrap(), "51.103.78.0/24"));
        assert!(ip_in_rule("51.103.79.1".parse().unwrap(), "0.0.0.0/0"));
        assert!(ip_in_rule("2001:db8::1".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_rule("2001:db9::1".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_rule("51.103.78.171".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_rule("51.103.78.171".parse().unwrap(), "not-an-ip"));
    }

    #[test]
    fn client_verdict_follows_public_access_and_ip_rules() {
        let mut info =
            VaultInfo { firewall: Some("Deny".into()), ip_rules: vec!["10.0.0.0/8".into()], ..VaultInfo::default() };
        let ip = "10.1.2.3".parse().unwrap();
        assert!(client_allowed(&info, ip));
        assert!(!client_allowed(&info, "192.0.2.1".parse().unwrap()));

        info.firewall = Some("Allow".into());
        assert!(client_allowed(&info, "192.0.2.1".parse().unwrap()));

        info.firewall = Some("Deny".into());
        info.public_network_access = Some("Disabled".into());
        assert!(!client_allowed(&info, ip));

        info.public_network_access = None;
        info.firewall = None;
        assert!(client_allowed(&info, ip));
    }
}
