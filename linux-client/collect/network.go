package collect

import "net"

// CollectIPAddresses returns non-loopback IP addresses (plain string form,
// no CIDR suffix) from every "up" network interface. No unit test - this
// depends on the real machine's actual network interfaces, which cannot be
// faked without an abstraction this small function doesn't need. Covered
// by live verification (Task 5) instead.
func CollectIPAddresses() []string {
	addrs := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range ifaceAddrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			addrs = append(addrs, ipNet.IP.String())
		}
	}
	return addrs
}
