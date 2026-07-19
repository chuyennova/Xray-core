//go:build windows

package wireguard

import (
	"context"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	windowsInterfaceMetric = 9000
	ipUnicastIf            = 31
	ipv6UnicastIf          = 31
)

type windowsLUIDDevice interface {
	tun.Device
	LUID() uint64
}

type kernelTun struct {
	tun.Device

	luid      winipcfg.LUID
	ifIndex   int
	name      string
	v4        netip.Addr
	v6        netip.Addr
	tcp4      *net.Dialer
	tcp6      *net.Dialer
	udp4      *net.ListenConfig
	udp6      *net.ListenConfig
	closeOnce sync.Once
	closeErr  error
}

func createKernelTun(localAddresses, dnsServers []netip.Addr, mtu int) (tdev tun.Device, tnet *Net, err error) {
	var v4, v6 netip.Addr
	prefixes := make([]netip.Prefix, 0, len(localAddresses))
	for _, addr := range localAddresses {
		if !addr.IsValid() {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		if addr.Is4() && !v4.IsValid() {
			v4 = addr
		}
		if addr.Is6() && !v6.IsValid() {
			v6 = addr
		}
	}
	if len(prefixes) == 0 {
		return nil, nil, fmt.Errorf("wireguard kernel TUN requires at least one local address")
	}

	name := calculateWindowsInterfaceName(localAddresses)
	wgt, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Wintun adapter %q: %w", name, err)
	}
	defer func() {
		if err != nil {
			_ = wgt.Close()
		}
	}()

	native, ok := wgt.(windowsLUIDDevice)
	if !ok {
		return nil, nil, fmt.Errorf("Wintun device %q does not expose a Windows LUID", name)
	}
	luid := winipcfg.LUID(native.LUID())
	if luid == 0 {
		return nil, nil, fmt.Errorf("Wintun device %q returned an invalid LUID", name)
	}

	t := &kernelTun{
		Device: wgt,
		luid:   luid,
		name:   name,
		v4:     v4,
		v6:     v6,
	}
	defer func() {
		if err != nil {
			_ = t.Close()
		}
	}()

	if err = luid.SetIPAddresses(prefixes); err != nil {
		return nil, nil, fmt.Errorf("failed to configure addresses on %q: %w", name, err)
	}

	if v4.IsValid() {
		if err = configureWindowsIPInterface(luid, windows.AF_INET, uint32(mtu)); err != nil {
			return nil, nil, fmt.Errorf("failed to configure IPv4 interface %q: %w", name, err)
		}
	}
	if v6.IsValid() {
		if err = configureWindowsIPInterface(luid, windows.AF_INET6, uint32(mtu)); err != nil {
			return nil, nil, fmt.Errorf("failed to configure IPv6 interface %q: %w", name, err)
		}
	}

	routes := make([]*winipcfg.RouteData, 0, 2)
	if v4.IsValid() {
		routes = append(routes, &winipcfg.RouteData{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHop:     netip.IPv4Unspecified(),
			Metric:      0,
		})
	}
	if v6.IsValid() {
		routes = append(routes, &winipcfg.RouteData{
			Destination: netip.MustParsePrefix("::/0"),
			NextHop:     netip.IPv6Unspecified(),
			Metric:      0,
		})
	}
	if err = luid.SetRoutes(routes); err != nil {
		return nil, nil, fmt.Errorf("failed to configure routes on %q: %w", name, err)
	}

	ifaceRow, err := luid.Interface()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read interface %q: %w", name, err)
	}
	ifIndex := int(ifaceRow.InterfaceIndex)
	if ifIndex <= 0 {
		return nil, nil, fmt.Errorf("Wintun interface %q has an invalid index", name)
	}

	t.ifIndex = ifIndex
	if v4.IsValid() {
		t.tcp4 = newWindowsTCPDialer("tcp4", v4, ifIndex)
		t.udp4 = newWindowsListenConfig("udp4", ifIndex)
	}
	if v6.IsValid() {
		t.tcp6 = newWindowsTCPDialer("tcp6", v6, ifIndex)
		t.udp6 = newWindowsListenConfig("udp6", ifIndex)
	}

	tnet = &Net{
		DialContextTCPAddrPort: t.DialContextTCPAddrPort,
		DialUDPAddrPort:        t.DialUDPAddrPort,
		dnsServers:             dnsServers,
		hasV4:                  v4.IsValid(),
		hasV6:                  v6.IsValid(),
	}

	xerrors.LogWarning(context.Background(), "Using Windows Winsock kernel TUN: interface=", name, " index=", ifIndex, " mtu=", mtu)
	return t, tnet, nil
}

func configureWindowsIPInterface(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu uint32) error {
	row, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	row.DadTransmits = 0
	row.ManagedAddressConfigurationSupported = false
	row.OtherStatefulConfigurationSupported = false
	row.NLMTU = mtu
	row.UseAutomaticMetric = false
	row.Metric = windowsInterfaceMetric
	return row.Set()
}

func calculateWindowsInterfaceName(localAddresses []netip.Addr) string {
	parts := make([]string, 0, len(localAddresses))
	for _, addr := range localAddresses {
		if addr.IsValid() {
			parts = append(parts, addr.String())
		}
	}
	sort.Strings(parts)
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.Join(parts, ",")))
	return fmt.Sprintf("Local Area Connection %010d", h.Sum32())
}

func newWindowsTCPDialer(network string, localAddr netip.Addr, ifIndex int) *net.Dialer {
	d := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IP(localAddr.AsSlice())},
	}
	d.Control = windowsInterfaceControl(network, ifIndex)
	return d
}

func newWindowsListenConfig(network string, ifIndex int) *net.ListenConfig {
	lc := &net.ListenConfig{}
	lc.Control = windowsInterfaceControl(network, ifIndex)
	return lc
}

func windowsInterfaceControl(expectedNetwork string, ifIndex int) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		controlErr := raw.Control(func(fd uintptr) {
			switch expectedNetwork {
			case "tcp4", "udp4":
				var indexBytes [4]byte
				binary.BigEndian.PutUint32(indexBytes[:], uint32(ifIndex))
				index := *(*uint32)(unsafe.Pointer(&indexBytes[0]))
				socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(index))
			case "tcp6", "udp6":
				socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, ifIndex)
			default:
				socketErr = fmt.Errorf("unsupported Windows kernel TUN network %q", network)
			}
		})
		if controlErr != nil {
			return controlErr
		}
		return socketErr
	}
}

func (t *kernelTun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid TCP destination")
	}
	if addr.Addr().Is4() {
		if t.tcp4 == nil {
			return nil, fmt.Errorf("IPv4 is not configured on %q", t.name)
		}
		return t.tcp4.DialContext(ctx, "tcp4", addr.String())
	}
	if t.tcp6 == nil {
		return nil, fmt.Errorf("IPv6 is not configured on %q", t.name)
	}
	return t.tcp6.DialContext(ctx, "tcp6", addr.String())
}

func (t *kernelTun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	if !raddr.IsValid() {
		return nil, fmt.Errorf("invalid UDP destination")
	}

	var (
		lc        *net.ListenConfig
		network   string
		localIP   netip.Addr
		localPort uint16
	)
	if raddr.Addr().Is4() {
		lc, network, localIP = t.udp4, "udp4", t.v4
	} else {
		lc, network, localIP = t.udp6, "udp6", t.v6
	}
	if lc == nil || !localIP.IsValid() {
		return nil, fmt.Errorf("address family is not configured on %q", t.name)
	}
	if laddr.IsValid() {
		if laddr.Addr().BitLen() != localIP.BitLen() {
			return nil, fmt.Errorf("UDP local and remote address families do not match")
		}
		localIP = laddr.Addr()
		localPort = laddr.Port()
	}

	bindAddress := net.JoinHostPort(localIP.String(), strconv.Itoa(int(localPort)))
	packetConn, err := lc.ListenPacket(context.Background(), network, bindAddress)
	if err != nil {
		return nil, err
	}
	return &internet.PacketConnWrapper{
		PacketConn: packetConn,
		Dest:       net.UDPAddrFromAddrPort(raddr),
	}, nil
}

func (t *kernelTun) Close() error {
	t.closeOnce.Do(func() {
		var errs []error
		if t.luid != 0 {
			if err := t.luid.FlushRoutes(windows.AF_UNSPEC); err != nil {
				errs = append(errs, fmt.Errorf("failed to flush routes on %q: %w", t.name, err))
			}
			if err := t.luid.FlushIPAddresses(windows.AF_UNSPEC); err != nil {
				errs = append(errs, fmt.Errorf("failed to flush addresses on %q: %w", t.name, err))
			}
		}
		if t.Device != nil {
			if err := t.Device.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close Wintun adapter %q: %w", t.name, err))
			}
		}
		t.closeErr = goerrors.Join(errs...)
	})
	return t.closeErr
}

func KernelTunSupported() (bool, error) {
	// Return true deliberately. If Wintun is missing or the process is not elevated,
	// createKernelTun fails and Xray stops instead of silently falling back to gVisor.
	return true, nil
}
