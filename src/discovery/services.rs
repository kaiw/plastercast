/// Well-known mDNS-discoverable services
pub enum DiscoverServices {
    GoogleCast,
}

impl DiscoverServices {
    pub fn service_string(&self) -> String {
        let name = match *self {
            DiscoverServices::GoogleCast => "_googlecast._tcp.local",
        };
        String::from(name)
    }
}
