extern crate mdns;

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use log::debug;

use crate::discovery::device::DeviceRecord;

pub struct DeviceDiscoveryCache {
    // TODO: Track record time and TTL, and flush entries from the cache.
    service_name: String,
    device_records: Arc<Mutex<HashSet<DeviceRecord>>>,
    poll_start_time: Instant,
    poll_finish_time: Arc<Mutex<Instant>>,
    pub timeout_ms: Duration,
}

impl DeviceDiscoveryCache {
    /// Discovery timeout in milliseconds
    const DEFAULT_TIMEOUT_MS: Duration = Duration::from_millis(2000);

    pub fn new(service_name: String) -> Self {
        let now = Instant::now();

        DeviceDiscoveryCache {
            service_name,
            device_records: Arc::new(Mutex::new(HashSet::new())),
            poll_start_time: now,
            poll_finish_time: Arc::new(Mutex::new(now)),
            timeout_ms: Self::DEFAULT_TIMEOUT_MS,
        }
    }

    /// Search for advertised mDNS devices
    ///
    /// This starts an mDNS discovery poll in a thread, updating the cache's
    /// list of discovered devices when the discovery timeout expires.
    pub fn start_discovery(&mut self) {
        if !self.is_discovery_running() {
            self.poll_start_time = Instant::now();

            let poll_time = Arc::clone(&self.poll_finish_time);
            let data = Arc::clone(&self.device_records);
            let timeout_ms = self.timeout_ms;
            let service_name = self.service_name.clone();

            thread::spawn(move || {
                let responses = mdns::discover::all(service_name)
                    .unwrap()
                    .timeout(timeout_ms);

                // Create devices from mDNS responses and insert them into the
                // device discovery cache.
                for response in responses {
                    if let Ok(response) = response {
                        if let Some(record) = DeviceRecord::from_mdns(&response) {
                            let mut records = data.lock().unwrap();
                            records.insert(record.clone());
                        }
                    }
                }

                let mut last_poll = poll_time.lock().unwrap();
                *last_poll = Instant::now();
            });
        } else {
            debug!("Discovery already running; not restarting");
        }
    }

    /// Return whether a discovery poll is currently running
    pub fn is_discovery_running(&self) -> bool {
        let poll_finish_time = self.poll_finish_time.lock().unwrap();
        self.poll_start_time > *poll_finish_time
    }

    /// Get the set of devices that have been discovered
    pub fn devices(&self) -> HashSet<DeviceRecord> {
        self.device_records.lock().unwrap().clone()
    }
}
