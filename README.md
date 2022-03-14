# auto-add-route

I don't know how to name this small CLI program.

It intercepts DNS query responses on local machine, collects IP addresses associated with some specific domain suffices
and add static routes to system routing table so that traffic to all these IPs will be sent to a different gateway
instead of the default one.

I write this small utility because the VPN connection to my office does not
support [split tunneling](https://en.wikipedia.org/wiki/Split_tunneling).

By the way, this is my first attempt to write something in Rust.
