package main

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
)

type Proxy struct {
	pluginsGlobals                PluginsGlobals
	serversInfo                   ServersInfo
	questionSizeEstimator         QuestionSizeEstimator
	registeredServers             []RegisteredServer
	dns64Resolvers                []string
	dns64Prefixes                 []string
	serversBlockingFragments      []string
	ednsClientSubnets             []*net.IPNet
	queryLogIgnoredQtypes         []string
	localDoHListeners             []*net.TCPListener
	queryMeta                     []string
	udpListeners                  []*net.UDPConn
	sources                       []*Source
	tcpListeners                  []*net.TCPListener
	registeredRelays              []RegisteredServer
	listenAddresses               []string
	localDoHListenAddresses       []string
	xTransport                    *XTransport
	allWeeklyRanges               *map[string]WeeklyRanges
	routes                        *map[string][]string
	captivePortalMap              *CaptivePortalMap
	nxLogFormat                   string
	localDoHCertFile              string
	localDoHCertKeyFile           string
	captivePortalMapFile          string
	localDoHPath                  string
	mainProto                     string
	cloakFile                     string
	forwardFile                   string
	blockIPFormat                 string
	blockIPLogFile                string
	allowedIPFile                 string
	allowedIPFormat               string
	allowedIPLogFile              string
	queryLogFormat                string
	blockIPFile                   string
	allowNameFile                 string
	allowNameFormat               string
	allowNameLogFile              string
	blockNameLogFile              string
	blockNameFormat               string
	blockNameFile                 string
	queryLogFile                  string
	blockedQueryResponse          string
	userName                      string
	nxLogFile                     string
	proxySecretKey                [32]byte
	proxyPublicKey                [32]byte
	ServerNames                   []string
	DisabledServerNames           []string
	requiredProps                 stamps.ServerInformalProperties
	certRefreshDelayAfterFailure  time.Duration
	timeout                       time.Duration
	certRefreshDelay              time.Duration
	certRefreshConcurrency        int
	cacheSize                     int
	logMaxBackups                 int
	logMaxAge                     int
	logMaxSize                    int
	cacheNegMinTTL                uint32
	rejectTTL                     uint32
	cacheMaxTTL                   uint32
	clientsCount                  uint32
	maxClients                    uint32
	cacheMinTTL                   uint32
	cacheNegMaxTTL                uint32
	cloakTTL                      uint32
	cloakedPTR                    bool
	cache                         bool
	pluginBlockIPv6               bool
	ephemeralKeys                 bool
	pluginBlockUnqualified        bool
	showCerts                     bool
	certIgnoreTimestamp           bool
	skipAnonIncompatibleResolvers bool
	anonDirectCertFallback        bool
	pluginBlockUndelegated        bool
	child                         bool
	SourceIPv4                    bool
	SourceIPv6                    bool
	SourceDNSCrypt                bool
	SourceDoH                     bool
	SourceODoH                    bool
}

func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
	proxy.udpListeners = append(proxy.udpListeners, conn)
}

func (proxy *Proxy) registerTCPListener(listener *net.TCPListener) {
	proxy.tcpListeners = append(proxy.tcpListeners, listener)
}

func (proxy *Proxy) registerLocalDoHListener(listener *net.TCPListener) {
	proxy.localDoHListeners = append(proxy.localDoHListeners, listener)
}

func (proxy *Proxy) addDNSListener(listenAddrStr string) {
	udp := "udp"
	tcp := "tcp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		udp = "udp4"
		tcp = "tcp4"
	}
	listenUDPAddr, err := net.ResolveUDPAddr(udp, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenTCPAddr, err := net.ResolveTCPAddr(tcp, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	// if 'userName' is not set, continue as before
	if len(proxy.userName) <= 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	// if 'userName' is set and we are the parent process
	if !proxy.child {
		// parent
		listenerUDP, err := net.ListenUDP(udp, listenUDPAddr)
		if err != nil {
			dlog.Fatal(err)
		}
		listenerTCP, err := net.ListenTCP(tcp, listenTCPAddr)
		if err != nil {
			dlog.Fatal(err)
		}

		fdUDP, err := listenerUDP.File() // On Windows, the File method of UDPConn is not implemented.
		if err != nil {
			dlog.Fatalf("Unable to switch to a different user: %v", err)
		}
		fdTCP, err := listenerTCP.File() // On Windows, the File method of TCPListener is not implemented.
		if err != nil {
			dlog.Fatalf("Unable to switch to a different user: %v", err)
		}
		defer listenerUDP.Close()
		defer listenerTCP.Close()
		FileDescriptors = append(FileDescriptors, fdUDP)
		FileDescriptors = append(FileDescriptors, fdTCP)
		return
	}

	// child
	listenerUDP, err := net.FilePacketConn(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerUDP"))
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	dlog.Noticef("Now listening to %v [UDP]", listenUDPAddr)
	proxy.registerUDPListener(listenerUDP.(*net.UDPConn))

	dlog.Noticef("Now listening to %v [TCP]", listenAddrStr)
	proxy.registerTCPListener(listenerTCP.(*net.TCPListener))
}

func (proxy *Proxy) addLocalDoHListener(listenAddrStr string) {
	network := "tcp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "tcp4"
	}
	listenTCPAddr, err := net.ResolveTCPAddr(network, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	// if 'userName' is not set, continue as before
	if len(proxy.userName) <= 0 {
		if err := proxy.localDoHListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	// if 'userName' is set and we are the parent process
	if !proxy.child {
		// parent
		listenerTCP, err := net.ListenTCP(network, listenTCPAddr)
		if err != nil {
			dlog.Fatal(err)
		}
		fdTCP, err := listenerTCP.File() // On Windows, the File method of TCPListener is not implemented.
		if err != nil {
			dlog.Fatalf("Unable to switch to a different user: %v", err)
		}
		defer listenerTCP.Close()
		FileDescriptors = append(FileDescriptors, fdTCP)
		return
	}

	// child

	listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	proxy.registerLocalDoHListener(listenerTCP.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddrStr, proxy.localDoHPath)
}

func (proxy *Proxy) StartProxy() {
	proxy.questionSizeEstimator = NewQuestionSizeEstimator()
	if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
		dlog.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	proxy.startAcceptingClients()
	if !proxy.child {
		// Notify the service manager that dnscrypt-proxy is ready. dnscrypt-proxy manages itself in case
		// servers are not immediately live/reachable. The service manager may assume it is initialized and
		// functioning properly. Note that the service manager 'Ready' signal is delayed if netprobe
		// cannot reach the internet during start-up.
		if err := ServiceManagerReadyNotify(); err != nil {
			dlog.Fatal(err)
		}
	}
	proxy.xTransport.internalResolverReady = false
	proxy.xTransport.internalResolvers = proxy.listenAddresses
	liveServers, err := proxy.serversInfo.refresh(proxy)
	if liveServers > 0 {
		proxy.certIgnoreTimestamp = false
	}
	if proxy.showCerts {
		os.Exit(0)
	}
	if liveServers > 0 {
		dlog.Noticef("dnscrypt-proxy is ready - live servers: %d", liveServers)
	} else if err != nil {
		dlog.Error(err)
		dlog.Notice("dnscrypt-proxy is waiting for at least one server to be reachable")
	}
	go func() {
		for {
			clocksmith.Sleep(PrefetchSources(proxy.xTransport, proxy.sources))
			proxy.updateRegisteredServers()
			runtime.GC()
		}
	}()
	if len(proxy.serversInfo.registeredServers) > 0 {
		go func() {
			for {
				delay := proxy.certRefreshDelay
				if liveServers == 0 {
					delay = proxy.certRefreshDelayAfterFailure
				}
				clocksmith.Sleep(delay)
				liveServers, _ = proxy.serversInfo.refresh(proxy)
				if liveServers > 0 {
					proxy.certIgnoreTimestamp = false
				}
				runtime.GC()
			}
		}()
	}
}

func (proxy *Proxy) updateRegisteredServers() error {
	for _, source := range proxy.sources {
		registeredServers, err := source.Parse()
		if err != nil {
			if len(registeredServers) == 0 {
				dlog.Criticalf("Unable to use source [%s]: [%s]", source.name, err)
				return err
			}
			dlog.Warnf(
				"Error in source [%s]: [%s] -- Continuing with reduced server count [%d]",
				source.name,
				err,
				len(registeredServers),
			)
		}
		for _, registeredServer := range registeredServers {
			if registeredServer.stamp.Proto != stamps.StampProtoTypeDNSCryptRelay &&
				registeredServer.stamp.Proto != stamps.StampProtoTypeODoHRelay {
				if len(proxy.ServerNames) > 0 {
					if !includesName(proxy.ServerNames, registeredServer.name) {
						continue
					}
				} else if registeredServer.stamp.Props&proxy.requiredProps != proxy.requiredProps {
					continue
				}
			}
			if includesName(proxy.DisabledServerNames, registeredServer.name) {
				continue
			}
			if proxy.SourceIPv4 || proxy.SourceIPv6 {
				isIPv4, isIPv6 := true, false
				if registeredServer.stamp.Proto == stamps.StampProtoTypeDoH {
					isIPv4, isIPv6 = true, true
				}
				if strings.HasPrefix(registeredServer.stamp.ServerAddrStr, "[") {
					isIPv4, isIPv6 = false, true
				}
				if !(proxy.SourceIPv4 == isIPv4 || proxy.SourceIPv6 == isIPv6) {
					continue
				}
			}
			if registeredServer.stamp.Proto == stamps.StampProtoTypeDNSCryptRelay ||
				registeredServer.stamp.Proto == stamps.StampProtoTypeODoHRelay {
				var found bool
				for i, currentRegisteredRelay := range proxy.registeredRelays {
					if currentRegisteredRelay.name == registeredServer.name {
						found = true
						if currentRegisteredRelay.stamp.String() != registeredServer.stamp.String() {
							dlog.Infof(
								"Updating stamp for [%s] was: %s now: %s",
								registeredServer.name,
								currentRegisteredRelay.stamp.String(),
								registeredServer.stamp.String(),
							)
							proxy.registeredRelays[i].stamp = registeredServer.stamp
							dlog.Debugf("Total count of registered relays %v", len(proxy.registeredRelays))
						}
					}
				}
				if !found {
					dlog.Debugf("Adding [%s] to the set of available relays", registeredServer.name)
					proxy.registeredRelays = append(proxy.registeredRelays, registeredServer)
				}
			} else {
				if !((proxy.SourceDNSCrypt && registeredServer.stamp.Proto == stamps.StampProtoTypeDNSCrypt) ||
					(proxy.SourceDoH && registeredServer.stamp.Proto == stamps.StampProtoTypeDoH) ||
					(proxy.SourceODoH && registeredServer.stamp.Proto == stamps.StampProtoTypeODoHTarget)) {
					continue
				}
				var found bool
				for i, currentRegisteredServer := range proxy.registeredServers {
					if currentRegisteredServer.name == registeredServer.name {
						found = true
						if currentRegisteredServer.stamp.String() != registeredServer.stamp.String() {
							dlog.Infof("Updating stamp for [%s] was: %s now: %s", registeredServer.name, currentRegisteredServer.stamp.String(), registeredServer.stamp.String())
							proxy.registeredServers[i].stamp = registeredServer.stamp
						}
					}
				}
				if !found {
					dlog.Debugf("Adding [%s] to the set of wanted resolvers", registeredServer.name)
					proxy.registeredServers = append(proxy.registeredServers, registeredServer)
					dlog.Debugf("Total count of registered servers %v", len(proxy.registeredServers))
				}
			}
		}
	}
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
	}
	for _, registeredRelay := range proxy.registeredRelays {
		proxy.serversInfo.registerRelay(registeredRelay.name, registeredRelay.stamp)
	}
	return nil
}

func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
	defer clientPc.Close()
	for {
		buffer := make([]byte, MaxDNSPacketSize-1)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return
		}
		packet := buffer[:length]
		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			proxy.processIncomingQuery(
				"udp",
				proxy.mainProto,
				packet,
				&clientAddr,
				clientPc,
				time.Now(),
				true,
			) // respond synchronously, but only to cached/synthesized queries
			continue
		}
		go func() {
			defer proxy.clientsCountDec()
			proxy.processIncomingQuery("udp", proxy.mainProto, packet, &clientAddr, clientPc, time.Now(), false)
		}()
	}
}

func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()
	for {
		clientPc, err := acceptPc.Accept()
		if err != nil {
			continue
		}
		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			clientPc.Close()
			continue
		}
		go func() {
			defer clientPc.Close()
			defer proxy.clientsCountDec()
			if err := clientPc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
				return
			}
			start := time.Now()
			packet, err := ReadPrefixed(&clientPc)
			if err != nil {
				return
			}
			clientAddr := clientPc.RemoteAddr()
			proxy.processIncomingQuery("tcp", "tcp", packet, &clientAddr, clientPc, start, false)
		}()
	}
}

func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) error {
	listenConfig, err := proxy.udpListenerConfig()
	if err != nil {
		return err
	}
	listenAddrStr := listenAddr.String()
	network := "udp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "udp4"
	}
	clientPc, err := listenConfig.ListenPacket(context.Background(), network, listenAddrStr)
	if err != nil {
		return err
	}
	proxy.registerUDPListener(clientPc.(*net.UDPConn))
	dlog.Noticef("Now listening to %v [UDP]", listenAddr)
	return nil
}

func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	listenAddrStr := listenAddr.String()
	network := "tcp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "tcp4"
	}
	acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
	if err != nil {
		return err
	}
	proxy.registerTCPListener(acceptPc.(*net.TCPListener))
	dlog.Noticef("Now listening to %v [TCP]", listenAddr)
	return nil
}

func (proxy *Proxy) localDoHListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	listenAddrStr := listenAddr.String()
	network := "tcp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "tcp4"
	}
	acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
	if err != nil {
		return err
	}
	proxy.registerLocalDoHListener(acceptPc.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddr, proxy.localDoHPath)
	return nil
}

func (proxy *Proxy) startAcceptingClients() {
	for _, clientPc := range proxy.udpListeners {
		go proxy.udpListener(clientPc)
	}
	proxy.udpListeners = nil
	for _, acceptPc := range proxy.tcpListeners {
		go proxy.tcpListener(acceptPc)
	}
	proxy.tcpListeners = nil
	for _, acceptPc := range proxy.localDoHListeners {
		go proxy.localDoHListener(acceptPc)
	}
	proxy.localDoHListeners = nil
}

func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
	anonymizedDNSHeader := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	relayedQuery := append(anonymizedDNSHeader, ip.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *encryptedQuery...)
	*encryptedQuery = relayedQuery
}

func (proxy *Proxy) exchangeWithUDPServer(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
) ([]byte, error) {
	upstreamAddr := serverInfo.UDPAddr
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		upstreamAddr = serverInfo.Relay.Dnscrypt.RelayUDPAddr
	}
	var err error
	var pc net.Conn
	proxyDialer := proxy.xTransport.proxyDialer
	if proxyDialer == nil {
		pc, err = net.DialTimeout("udp", upstreamAddr.String(), serverInfo.Timeout)
	} else {
		pc, err = (*proxyDialer).Dial("udp", upstreamAddr.String())
	}
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, err
	}
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &encryptedQuery)
	}
	encryptedResponse := make([]byte, MaxDNSPacketSize)
	for tries := 2; tries > 0; tries-- {
		if _, err := pc.Write(encryptedQuery); err != nil {
			return nil, err
		}
		length, err := pc.Read(encryptedResponse)
		if err == nil {
			encryptedResponse = encryptedResponse[:length]
			break
		}
		dlog.Debugf("[%v] Retry on timeout", serverInfo.Name)
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) exchangeWithTCPServer(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
) ([]byte, error) {
	upstreamAddr := serverInfo.TCPAddr
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		upstreamAddr = serverInfo.Relay.Dnscrypt.RelayTCPAddr
	}
	var err error
	var pc net.Conn
	proxyDialer := proxy.xTransport.proxyDialer
	if proxyDialer == nil {
		pc, err = net.DialTimeout("tcp", upstreamAddr.String(), serverInfo.Timeout)
	} else {
		pc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
	}
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, err
	}
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}
	encryptedQuery, err = PrefixWithSize(encryptedQuery)
	if err != nil {
		return nil, err
	}
	if _, err := pc.Write(encryptedQuery); err != nil {
		return nil, err
	}
	encryptedResponse, err := ReadPrefixed(&pc)
	if err != nil {
		return nil, err
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) clientsCountInc() bool {
	for {
		count := atomic.LoadUint32(&proxy.clientsCount)
		if count >= proxy.maxClients {
			return false
		}
		if atomic.CompareAndSwapUint32(&proxy.clientsCount, count, count+1) {
			dlog.Debugf("clients count: %d", count+1)
			return true
		}
	}
}

func (proxy *Proxy) clientsCountDec() {
	for {
		count := atomic.LoadUint32(&proxy.clientsCount)
		if count == 0 {
			// Already at zero, nothing to do
			break
		}
		if atomic.CompareAndSwapUint32(&proxy.clientsCount, count, count-1) {
			dlog.Debugf("clients count: %d", count-1)
			break
		}
		// CAS failed, retry with updated count
	}
}

func (proxy *Proxy) processIncomingQuery(
	clientProto string,
	serverProto string,
	query []byte,
	clientAddr *net.Addr,
	clientPc net.Conn,
	start time.Time,
	onlyCached bool,
) []byte {
	var response []byte
	if len(query) < MinDNSPacketSize {
		return response
	}
	pluginsState := NewPluginsState(proxy, clientProto, clientAddr, serverProto, start)
	serverName := "-"
	needsEDNS0Padding := false
	serverInfo := proxy.serversInfo.getOne()
	if serverInfo != nil {
		serverName = serverInfo.Name
		needsEDNS0Padding = (serverInfo.Proto == stamps.StampProtoTypeDoH || serverInfo.Proto == stamps.StampProtoTypeTLS)
	}
	query, _ = pluginsState.ApplyQueryPlugins(&proxy.pluginsGlobals, query, needsEDNS0Padding)
	if len(query) < MinDNSPacketSize || len(query) > MaxDNSPacketSize {
		return response
	}
	if pluginsState.action == PluginsActionDrop {
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return response
	}
	var err error
	if pluginsState.synthResponse != nil {
		response, err = pluginsState.synthResponse.PackBuffer(response)
		if err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			return response
		}
	}
	if onlyCached {
		if len(response) == 0 {
			return response
		}
		serverInfo = nil
	}
	if len(response) == 0 && serverInfo != nil {
		var ttl *uint32
		pluginsState.serverName = serverName
		if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
			sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, serverProto)
			if err != nil && serverProto == "udp" {
				dlog.Debug("Unable to pad for UDP, re-encrypting query for TCP")
				serverProto = "tcp"
				sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
			}
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				return response
			}
			serverInfo.noticeBegin(proxy)
			if serverProto == "udp" {
				response, err = proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
				retryOverTCP := false
				if err == nil && len(response) >= MinDNSPacketSize && response[2]&0x02 == 0x02 {
					retryOverTCP = true
				} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					dlog.Debugf("[%v] Retry over TCP after UDP timeouts", serverName)
					retryOverTCP = true
				}
				if retryOverTCP {
					serverProto = "tcp"
					sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
					if err != nil {
						pluginsState.returnCode = PluginsReturnCodeParseError
						pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
						return response
					}
					response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
				}
			} else {
				response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
			}
			if err != nil {
				if stale, ok := pluginsState.sessionData["stale"]; ok {
					dlog.Debug("Serving stale response")
					response, err = (stale.(*dns.Msg)).Pack()
				}
			}
			if err != nil {
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					pluginsState.returnCode = PluginsReturnCodeServerTimeout
				} else {
					pluginsState.returnCode = PluginsReturnCodeNetworkError
				}
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				serverInfo.noticeFailure(proxy)
				return response
			}
		} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
			tid := TransactionID(query)
			SetTransactionID(query, 0)
			serverInfo.noticeBegin(proxy)
			serverResponse, _, tls, _, err := proxy.xTransport.DoHQuery(serverInfo.useGet, serverInfo.URL, query, proxy.timeout)
			SetTransactionID(query, tid)

			if err != nil || tls == nil || !tls.HandshakeComplete {
				if stale, ok := pluginsState.sessionData["stale"]; ok {
					dlog.Debug("Serving stale response")
					response, err = (stale.(*dns.Msg)).Pack()
				}
			}
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeNetworkError
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				serverInfo.noticeFailure(proxy)
				return response
			}
			if response == nil {
				response = serverResponse
			}
			if len(response) >= MinDNSPacketSize {
				SetTransactionID(response, tid)
			}
		} else if serverInfo.Proto == stamps.StampProtoTypeODoHTarget {
			tid := TransactionID(query)
			if len(serverInfo.odohTargetConfigs) == 0 {
				return response
			}
			target := serverInfo.odohTargetConfigs[rand.Intn(len(serverInfo.odohTargetConfigs))]
			odohQuery, err := target.encryptQuery(query)
			if err != nil {
				dlog.Errorf("Failed to encrypt query for [%v]", serverName)
				response = nil
			} else {
				targetURL := serverInfo.URL
				if serverInfo.Relay != nil && serverInfo.Relay.ODoH != nil {
					targetURL = serverInfo.Relay.ODoH.URL
				}
				responseBody, responseCode, _, _, err := proxy.xTransport.ObliviousDoHQuery(serverInfo.useGet, targetURL, odohQuery.odohMessage, proxy.timeout)
				if err == nil && len(responseBody) > 0 && responseCode == 200 {
					response, err = odohQuery.decryptResponse(responseBody)
					if err != nil {
						dlog.Warnf("Failed to decrypt response from [%v]", serverName)
						response = nil
					}
				} else if responseCode == 401 || (responseCode == 200 && len(responseBody) == 0) {
					if responseCode == 200 {
						dlog.Warnf("ODoH relay for [%v] is buggy and returns a 200 status code instead of 401 after a key update", serverInfo.Name)
					}
					dlog.Infof("Forcing key update for [%v]", serverInfo.Name)
					for _, registeredServer := range proxy.serversInfo.registeredServers {
						if registeredServer.name == serverInfo.Name {
							if err = proxy.serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err != nil {
								// Failed to refresh the proxy server information.
								dlog.Noticef("Key update failed for [%v]", serverName)
								serverInfo.noticeFailure(proxy)
								clocksmith.Sleep(10 * time.Second)
							}
							break
						}
					}
					response = nil
				} else {
					dlog.Warnf("Failed to receive successful response from [%v]", serverName)
				}
			}

			if len(response) >= MinDNSPacketSize {
				SetTransactionID(response, tid)
			} else if response == nil {
				pluginsState.returnCode = PluginsReturnCodeNetworkError
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				serverInfo.noticeFailure(proxy)
				return response
			}
		} else {
			dlog.Fatal("Unsupported protocol")
		}
		if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			serverInfo.noticeFailure(proxy)
			return response
		}
		response, err = pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response, ttl)
		if err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			serverInfo.noticeFailure(proxy)
			return response
		}
		if pluginsState.action == PluginsActionDrop {
			pluginsState.returnCode = PluginsReturnCodeDrop
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			return response
		}
		if pluginsState.synthResponse != nil {
			response, err = pluginsState.synthResponse.PackBuffer(response)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				return response
			}
		}
		if rcode := Rcode(response); rcode == dns.RcodeServerFailure { // SERVFAIL
			if pluginsState.dnssec {
				dlog.Debug("A response had an invalid DNSSEC signature")
			} else {
				dlog.Infof("A response with status code 2 was received - this is usually a temporary, remote issue with the configuration of the domain name")
				serverInfo.noticeFailure(proxy)
			}
		} else {
			serverInfo.noticeSuccess(proxy)
		}
	}
	if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
		if len(response) == 0 {
			pluginsState.returnCode = PluginsReturnCodeNotReady
		} else {
			pluginsState.returnCode = PluginsReturnCodeParseError
		}
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		if serverInfo != nil {
			serverInfo.noticeFailure(proxy)
		}
		return response
	}
	if clientProto == "udp" {
		if len(response) > pluginsState.maxUnencryptedUDPSafePayloadSize {
			response, err = TruncatedResponse(response)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				return response
			}
		}
		clientPc.(net.PacketConn).WriteTo(response, *clientAddr)
		if HasTCFlag(response) {
			proxy.questionSizeEstimator.blindAdjust()
		} else {
			proxy.questionSizeEstimator.adjust(ResponseOverhead + len(response))
		}
	} else if clientProto == "tcp" {
		response, err = PrefixWithSize(response)
		if err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			if serverInfo != nil {
				serverInfo.noticeFailure(proxy)
			}
			return response
		}
		if clientPc != nil {
			clientPc.Write(response)
		}
	}
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)

	return response
}

func NewProxy() *Proxy {
	return &Proxy{
		serversInfo: NewServersInfo(),
	}
}
