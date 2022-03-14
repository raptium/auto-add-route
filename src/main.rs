use etherparse::SlicedPacket;
use log::{error, info, trace, warn};
use pcap::{Capture, Device};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{Name, RData, RecordType};

use clap::Parser;

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
}

struct DnsAutoRoutes {
    target: Ipv4Addr,
    alias: HashSet<Name>,
    corp_zones: Vec<Name>,
    net_if: Option<String>,
}

impl DnsAutoRoutes {
    pub fn new(args: &Args) -> DnsAutoRoutes {
        let target = Ipv4Addr::from_str(args.target.as_str()).unwrap();
        let corp_zones = args
            .domain_suffices
            .iter()
            .filter_map(|s| Name::from_utf8(s).ok())
            .collect();
        return DnsAutoRoutes {
            target,
            corp_zones,
            alias: HashSet::new(),
            net_if: args.net_if.clone(),
        };
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
