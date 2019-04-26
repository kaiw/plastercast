extern crate mdns;

use std::net::IpAddr;

use log::info;

const DEFAULT_NAME: &str = "Unnamed";

// TODO: Consider manually implementing Hash and Eq, so that (ip_addr, port)
// defines a unique device. If this happens, the device discovery cache will
// need handling for replacing an existing DeviceRecord in its discovered set.

/// Device details obtained via mDNS discovery
///
/// See https://blog.oakbits.com/google-cast-protocol-discovery-and-connection.html
///
/// # Missing record fields
///
/// Additional fields from the TXT record whose use is unknown are not
/// included here. These are:
///
///  * `cd` - 32-character hex string
///  * `rm` - only seen as blank
///  * `st` - only seen as 0
///  * `bs` - 12-character hex string
///  * `nf` - only seen as 1
///  * `rs` - only seen as blank
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceRecord {
    /// mDNS service address of the device
    pub ptr: Option<String>,

    /// IPv4/IPv6 address of the device
    pub ip_addr: IpAddr,

    /// Port on which the service is running
    pub port: u16,

    /// UUID of the device
    pub device_uuid: Option<String>,

    /// Human-readable model of the device, e.g., `Chromecast Ultra`
    pub model: Option<String>,

    /// Protocol version (possibly). According to other sources:
    ///  * 02: On ChromeCast 1 devices
    ///  * 04: On Nexus player devices
    ///  * 05: On ChromeCast audio devices
    ///
    /// though on all current devices it appears to be 05.
    pub version: Option<String>,

    /// URL path to an icon, accessible at the device's IP on port 8008.
    /// This is a permanent redirect to an outdated device image.
    pub icon_path: Option<String>,

    /// An integer somehow linked to a certificate authority. Different
    /// hardware iterations have different values here.
    pub certificate_authority: Option<String>,

    /// Friendly name assigned by the device owner, e.g., `Living room`
    pub friendly_name: Option<String>,
}

impl DeviceRecord {
    /// User-friendly display name
    pub fn display_name(&self) -> String {
        let default_name = &DEFAULT_NAME.to_string();
        let friendly_name = self.friendly_name.as_ref().unwrap_or(default_name);
        format!("{} ({})", friendly_name, self.ip_addr)
    }

    /// Constructs a [`DeviceRecord`] from an mDNS response, most likely from
    /// a discovery run against the Google Cast mDNS service name.
    pub fn from_mdns(response: &mdns::Response) -> Option<DeviceRecord> {
        let mut ptr: Option<String> = Default::default();
        let mut ip_addr: Option<IpAddr> = Default::default();
        let mut port: Option<u16> = Default::default();
        let mut device_uuid: Option<String> = Default::default();
        let mut model: Option<String> = Default::default();
        let mut version: Option<String> = Default::default();
        let mut icon_path: Option<String> = Default::default();
        let mut certificate_authority: Option<String> = Default::default();
        let mut friendly_name: Option<String> = Default::default();

        for dns_record in response.records() {
            match dns_record.kind {
                mdns::RecordKind::A(addr) => {
                    ip_addr = Some(addr.into());
                }
                mdns::RecordKind::AAAA(addr) => {
                    ip_addr = Some(addr.into());
                }
                mdns::RecordKind::SRV { port: srv_port, .. } => {
                    port = Some(srv_port);
                }
                mdns::RecordKind::TXT(ref records) => {
                    for record in records.iter() {
                        let splits: Vec<&str> = record.split('=').collect();

                        // Skip non-RFC1464 records
                        if splits.len() != 2 {
                            continue;
                        }

                        let key = splits[0];
                        let val = Some(String::from(splits[1]));
                        match key {
                            "ca" => certificate_authority = val,
                            "fn" => friendly_name = val,
                            "ic" => icon_path = val,
                            "id" => device_uuid = val,
                            "md" => model = val,
                            "ve" => version = val,
                            _ => (),
                        }
                    }
                }
                mdns::RecordKind::PTR(ref string) => {
                    ptr = Some(string.to_owned());
                }
                _ => (),
            }
        }

        if let Some(ip_addr) = ip_addr {
            if let Some(port) = port {
                Some(DeviceRecord {
                    ip_addr,
                    port,
                    ptr,
                    device_uuid,
                    model,
                    version,
                    icon_path,
                    certificate_authority,
                    friendly_name,
                })
            } else {
                info!("No SRV port record found; invalid device");
                None
            }
        } else {
            info!("No A/AAAA port record found; invalid device");
            None
        }
    }
}
