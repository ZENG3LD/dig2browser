//! Backend abstraction layer for dig2browser.
//!
//! `BrowserInner` and `PageInner` are private enum wrappers that allow
//! `StealthBrowser` and `StealthPage` to dispatch across the CDP (Chrome/Edge)
//! and WebDriver (Firefox) backends at runtime without any heap allocation or
//! `dyn` overhead. All Firefox code is gated behind the `firefox` cargo feature.

pub(crate) mod cdp;
#[cfg(feature = "firefox")]
pub(crate) mod webdriver;

pub(crate) use cdp::CdpBrowser;
#[cfg(feature = "firefox")]
pub(crate) use webdriver::WebDriverBrowser;

/// Private inner enum backing `StealthBrowser`.
pub(crate) enum BrowserInner {
    Cdp(CdpBrowser),
    #[cfg(feature = "firefox")]
    WebDriver(WebDriverBrowser),
}

/// Private inner enum backing `StealthPage`.
pub(crate) enum PageInner {
    Cdp(chromiumoxide::Page),
    #[cfg(feature = "firefox")]
    WebDriver(fantoccini::Client),
}
