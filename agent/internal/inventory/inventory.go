package inventory

import "net"

type System struct {
	Hostname     string
	OSName       string
	OSVersion    string
	Architecture string
	Details      map[string]interface{}
}

func subtractFloor(total, available uint64) uint64 {
	if available > total {
		return 0
	}
	return total - available
}

func ipAddresses() []string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return []string{}
	}
	result := []string{}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && !ip.IsLoopback() {
			result = append(result, ip.String())
		}
	}
	return result
}

// macAddresses reports every non-loopback interface's hardware address, so
// the server can offer Wake-on-LAN for this device without a separate
// discovery step. net.Interfaces() is already cross-platform, unlike most
// of this package's other collectors, so no Linux/Windows split is needed
// here.
func macAddresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}
	result := []string{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		result = append(result, iface.HardwareAddr.String())
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
