use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use url::Url;

pub const MAX_URL_BYTES: usize = 8 * 1024;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalUrl(String);

impl CanonicalUrl {
    pub fn parse(value: &str) -> Result<Self, CanonicalUrlError> {
        if value.len() > MAX_URL_BYTES {
            return Err(CanonicalUrlError(format!(
                "URL exceeds {MAX_URL_BYTES} bytes"
            )));
        }
        let mut url = Url::parse(value).map_err(|error| CanonicalUrlError(error.to_string()))?;
        canonicalize(&mut url)?;
        let canonical = url.to_string();
        if canonical.len() > MAX_URL_BYTES {
            return Err(CanonicalUrlError(format!(
                "canonical URL exceeds {MAX_URL_BYTES} bytes"
            )));
        }
        Ok(Self(canonical))
    }

    pub fn resolve(&self, reference: &str) -> Result<Self, CanonicalUrlError> {
        if reference.len() > MAX_URL_BYTES {
            return Err(CanonicalUrlError(format!(
                "URL reference exceeds {MAX_URL_BYTES} bytes"
            )));
        }
        let base = Url::parse(&self.0).map_err(|error| CanonicalUrlError(error.to_string()))?;
        let mut resolved = base
            .join(reference)
            .map_err(|error| CanonicalUrlError(error.to_string()))?;
        canonicalize(&mut resolved)?;
        let canonical = resolved.to_string();
        if canonical.len() > MAX_URL_BYTES {
            return Err(CanonicalUrlError(format!(
                "resolved URL exceeds {MAX_URL_BYTES} bytes"
            )));
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn parsed(&self) -> Url {
        Url::parse(&self.0).expect("CanonicalUrl always contains a validated URL")
    }
}

fn canonicalize(url: &mut Url) -> Result<(), CanonicalUrlError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CanonicalUrlError(
            "only http and https URLs are crawlable".to_owned(),
        ));
    }
    if url.host_str().is_none() {
        return Err(CanonicalUrlError("URL must have a host".to_owned()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CanonicalUrlError(
            "URLs containing credentials are not crawlable".to_owned(),
        ));
    }

    url.set_fragment(None);
    if url.query() == Some("") {
        url.set_query(None);
    }

    let default_port = match url.scheme() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    if url.port() == default_port {
        url.set_port(None)
            .map_err(|_| CanonicalUrlError("could not normalize URL port".to_owned()))?;
    }
    Ok(())
}

impl fmt::Debug for CanonicalUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CanonicalUrl").field(&self.0).finish()
    }
}

impl fmt::Display for CanonicalUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for CanonicalUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CanonicalUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalUrlError(pub(crate) String);

impl fmt::Display for CanonicalUrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalUrlError {}

#[cfg(test)]
mod tests {
    use super::CanonicalUrl;

    #[test]
    fn canonicalization_removes_fragment_and_default_port() {
        let url = CanonicalUrl::parse("HTTPS://Example.COM:443/a/../b?q=1#fragment").unwrap();
        assert_eq!(url.as_str(), "https://example.com/b?q=1");
    }

    #[test]
    fn credentials_and_non_http_schemes_are_rejected() {
        assert!(CanonicalUrl::parse("https://user:secret@example.com/").is_err());
        assert!(CanonicalUrl::parse("file:///tmp/page.html").is_err());
    }
}
