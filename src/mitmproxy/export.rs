//! Export exact observed hostnames as mitmproxy `allow_hosts` expressions.
use crate::wireshark::{AnalysisReport, DomainSource};

impl AnalysisReport {
    /// Sorted connection hostnames. DNS-only hints are deliberately excluded.
    pub fn interception_domains(&self) -> Vec<&str> {
        self.domains
            .iter()
            .filter(|d| {
                d.sources.iter().any(|s| *s != DomainSource::DnsQuery)
                    && crate::wireshark::normalize_hostname(&d.name).as_deref()
                        == Some(d.name.as_str())
            })
            .map(|d| d.name.as_str())
            .collect()
    }

    pub fn domains_text(&self) -> String {
        let domains = self.interception_domains();
        if domains.is_empty() {
            String::new()
        } else {
            format!("{}\n", domains.join("\n"))
        }
    }

    /// YAML fragment for `mitmdump --set confdir=...` or an existing config.yaml.
    /// An empty discovery set uses a never-matching expression: [] allows all hosts.
    pub fn mitmproxy_config(&self) -> String {
        let mut config = String::from(
            "# Observed connection hostnames only; DNS-only hints excluded.\nallow_hosts:\n",
        );
        let domains = self.interception_domains();
        if domains.is_empty() {
            config.push_str("  - '(?!)'\n");
        }
        for name in domains {
            let escaped = name.replace('.', "\\.");
            config.push_str(&format!("  - '^{escaped}(?::[0-9]+)?$'\n"));
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireshark::DomainObservation;
    #[test]
    fn exports_exact_hosts_and_excludes_dns_only_hints() {
        let report = AnalysisReport {
            domains: vec![
                DomainObservation {
                    name: "example.com".into(),
                    sources: [DomainSource::TlsSni].into(),
                    ..Default::default()
                },
                DomainObservation {
                    name: "query-only.com".into(),
                    sources: [DomainSource::DnsQuery].into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(report.domains_text(), "example.com\n");
        assert!(
            report
                .mitmproxy_config()
                .contains("'^example\\.com(?::[0-9]+)?$'")
        );
        assert!(!report.mitmproxy_config().contains("query-only"));
        assert!(
            AnalysisReport::default()
                .mitmproxy_config()
                .contains("'(?!)'")
        );
    }
}
