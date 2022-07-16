use std::collections::HashSet;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use clap::Parser;
use etherparse::SlicedPacket;
use log::{error, info, trace, warn};
use pcap::{Capture, Device};
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{Name, RData, RecordType};

use crate::store::{init_dns_log_store, LogEntry};

mod store;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Route target IP
    target: String,
    /// Suffices of domains that should be routed via target IP
    domain_suffices: Vec<String>,
    /// Network interface to capture DNS traffics on
    #[clap(short = 'i', long)]
    net_if: Option<String>,
    /// Path of database to store recent DNS query history
    #[clap(short = 'd', long, value_parser, value_hint = clap::ValueHint::FilePath)]
    db_path: Option<String>,
}

struct DnsAutoRoutes<'a> {
    target: Ipv4Addr,
    alias: HashSet<Name>,
    corp_zones: Vec<Name>,
    net_if: Option<String>,
    store: Option<Box<dyn store::DnsLogStore + 'a>>,
}

fn replay_logged_entries(entries: Vec<LogEntry>) {
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(1)); // delay 1 sec
        for entry in entries {
            let addr_port = format!("{}:80", entry.host);
            match addr_port.to_socket_addrs() {
                Ok(_) => info!("Resolving logged entry {}", entry.host),
                Err(e) => warn!("failed to resolving logged entry {}: {}", entry.host, e),
            }
        }
    });
}

impl<'a> DnsAutoRoutes<'a> {
    pub fn new(args: &Args) -> DnsAutoRoutes {
        let target = Ipv4Addr::from_str(args.target.as_str()).unwrap();
        let corp_zones = args
            .domain_suffices
            .iter()
            .filter_map(|s| Name::from_utf8(s).ok())
            .collect();
        let store = match &args.db_path {
            None => None,
            Some(path) => Some(init_dns_log_store(path).unwrap()),
        };
        DnsAutoRoutes {
            target,
            corp_zones,
            alias: HashSet::new(),
            net_if: args.net_if.clone(),
            store,
        }
    }

    pub fn start(&mut self) {
        info!(
            "Domain Suffices: {}",
            self.corp_zones
                .iter()
                .map(|z| { z.to_utf8() })
                .collect::<Vec<String>>()
                .join(", ")
        );
        info!("Target IP: {}", self.target);
        let device = match &self.net_if {
            Some(if_name) => Device::from(if_name.as_str()),
            _ => Device::lookup().unwrap(),
        };
        info!("Capture on {:?}", device.name);
        let mut cap = Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .immediate_mode(true)
            .open()
            .unwrap();
        let logged_entries = self.load_logged_entries();
        match logged_entries {
            None => info!("No logged entries loaded from DB."),
            Some(e) => {
                info!("{} logged entries loaded from DB.", e.len());
                replay_logged_entries(e)
            }
        }
        cap.filter("udp port 53", true).unwrap();
        while let Ok(packet) = cap.next() {
            match SlicedPacket::from_ethernet(packet.data) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => match Message::from_vec(value.payload) {
                    Err(value) => println!("Err {:?}", value),
                    Ok(value) => {
                        if value.header().message_type() == MessageType::Response {
                            self.log_dns_response(&value);
                        }
                    }
                },
            }
        }
    }

    fn load_logged_entries(&self) -> Option<Vec<LogEntry>> {
        if self.store.is_none() {
            return None;
        }
        let store = self.store.as_ref().unwrap();
        let entries = store.load_entries();
        match entries {
            Ok(e) => Some(e),
            Err(_) => None,
        }
    }

    fn add_vpn_route(&self, ip: &str) {
        match Command::new("route")
            .arg("-n")
            .arg("add")
            .arg("-host")
            .arg(ip)
            .arg(self.target.to_string())
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    warn!("Failed to add route: {:?}", output.stderr);
                }
            }
            Err(e) => error!("Failed to add route: {:?}", e),
        }
    }

    fn on_query_corp(&mut self, host: &str) {
        if self.store.is_none() {
            return;
        }
        let store = self.store.as_mut().unwrap();
        let r = store.on_query(host.trim_end_matches("."));
        match r {
            Ok(_) => {}
            Err(_) => warn!("Failed to log dns entry in store: {}", host),
        }
    }

    fn log_dns_response(&mut self, msg: &Message) {
        for ans in msg.answers() {
            let mut is_corp = false;
            let is_alias = self.alias.contains(&ans.name());
            for zone in self.corp_zones.iter() {
                if zone.zone_of(ans.name()) {
                    is_corp = true;
                    break;
                }
            }
            if is_corp {
                self.on_query_corp(&ans.name().to_string())
            }
            match (ans.rr_type(), ans.data()) {
                (RecordType::A, Some(RData::A(addr))) => {
                    trace!("Answer: {} {} {}", ans.name(), ans.rr_type(), addr);
                    if is_corp || is_alias {
                        self.add_vpn_route(&addr.to_string());
                    }
                }
                (RecordType::CNAME, Some(RData::CNAME(cname))) => {
                    trace!("Answer: {} {} {}", ans.name(), ans.rr_type(), cname);
                    if is_corp {
                        let _ = &self.alias.insert(cname.clone());
                    }
                }
                _ => {}
            }
        }
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let mut s = DnsAutoRoutes::new(&args);
    s.start();
}
