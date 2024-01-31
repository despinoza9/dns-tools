package tools

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miekg/pkcs11"
)

// Context contains the state of a zone signing process.
type Context struct {
	Config         *ContextConfig
	File           io.Reader             // zone path
	Output         io.WriteCloser        // Out path
	rrs            RRArray               // rrs
	soa            *dns.SOA              // SOA RR
	zonemdMap      map[uint8]*dns.ZONEMD // ZONEMD RRs with map
	Log            *log.Logger           // Logger
	SignAlgorithm  SignAlgorithm         // Sign Algorithm
	DelegatedZones map[string]struct{}   // Map with Delegated zones.
	WithDS         map[string]struct{}   // Map with zones with a DS RR
	DNSKEYS        struct {
		ZSK, KSK map[uint16]*dns.DNSKEY // DNSKEYS
	}
}

// ContextConfig contains the common args to sign and verify files
type ContextConfig struct {
	Zone            string    // Zone name
	CreateKeys      bool      // If True, the sign process creates new keys for the signature.
	NSEC3           bool      // If true, the zone is signed using NSEC3
	OptOut          bool      // If true and NSEC3 is true, the zone is signed using OptOut NSEC3 flag.
	DigestEnabled   bool      // If true, the zone is hashed and DigestEnabled is used
	SignAlgorithm   string    // Signature algorithm
	FilePath        string    // Output Path
	OutputPath      string    // Output Path
	RRSIGExpDate    time.Time // RRSIG Expiration Date
	Info            bool      // If true, a credits txt will be added to _dnstools subdomain.
	Lazy            bool      // If true, the zone will not be signed if it is not needed.
	VerifyThreshold time.Time // Verification Threshold
	HashAlg         uint8     // 1:sha384 (default), 2:sha512
	NSEC3Iterations uint16
	NSEC3SaltLength uint8
	NSEC3SaltValue  string
}

// NewContext creates a new context based on a configuration structure. It also receives
// a logger to log errors.
func NewContext(config *ContextConfig, log *log.Logger) (ctx *Context, err error) {
	algorithm := StringToSignAlgorithm[config.SignAlgorithm] // It could be nil
	ctx = &Context{
		Config:        config,
		Log:           log,
		SignAlgorithm: algorithm,
	}

	if len(config.FilePath) > 0 {
		f, err := os.Open(config.FilePath)
		if err != nil {
			return nil, err
		}
		ctx.File = f
	} else {
		ctx.File = os.Stdin
	}

	if len(config.OutputPath) > 0 {
		writer, err := os.Create(config.OutputPath)
		if err != nil {
			return nil, fmt.Errorf("couldn't create out file in path %s: %s", config.OutputPath, err)
		}
		ctx.Output = writer
	} else {
		ctx.Output = os.Stdout
	}
	return ctx, nil
}

// Check if a ZONEMD already exists .
func (ctx *Context) isZONEMDAlready(newmd *dns.ZONEMD) bool {
	_, exists := ctx.zonemdMap[newmd.Hash]
	return exists
}

// ReadAndParseZone parses a DNS zone file and returns an array of rrs and the zone minTTL.
// It also updates the serial in the SOA record if updateSerial is true.
// If setCredits is true, it adds a TXT record to the zone, under the subdomain _dnstools, with signing information
// Returns the SOA.
// IT DOES NOT SORT THE RR LIST
func (ctx *Context) ReadAndParseZone(updateSerial bool) error {
	ctx.Log.Printf("Reading and parsing zone %s (updateSerial=%t)", ctx.Config.Zone, updateSerial)
	if ctx.soa != nil {
		return nil
	}
	if ctx.File == nil {
		return fmt.Errorf("no file defined on context")
	}
	delegatedZones := make(map[string]struct{})

	if ctx.WithDS == nil {
		ctx.WithDS = make(map[string]struct{})
	}

	if ctx.DNSKEYS.KSK == nil {
		ctx.DNSKEYS.KSK = make(map[uint16]*dns.DNSKEY)
	}

	if ctx.DNSKEYS.ZSK == nil {
		ctx.DNSKEYS.ZSK = make(map[uint16]*dns.DNSKEY)
	}
	if ctx.zonemdMap == nil {
		ctx.zonemdMap = make(map[uint8]*dns.ZONEMD)
	}

	rrs := make(RRArray, 0)

	if len(ctx.Config.Zone) > 0 && !strings.HasSuffix(ctx.Config.Zone, ".") {
		ctx.Config.Zone += "."
	}

	zoneMDMap := make(map[uint8]*dns.ZONEMD)
	zone := dns.NewZoneParser(ctx.File, ctx.Config.Zone, "")
	if err := zone.Err(); err != nil {
		return err
	}
	for rr, ok := zone.Next(); ok; rr, ok = zone.Next() {
		// I hate you RFC 4034, Section 6.2
		rr.Header().Name = NormalizeFQDN(rr.Header().Name)

		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			if ctx.soa != nil {
				continue // parse only one SOA
			}

			// I hate you RFC 4034, Section 6.2
			rr.(*dns.SOA).Ns = strings.ToLower(rr.(*dns.SOA).Ns)
			rr.(*dns.SOA).Mbox = strings.ToLower(rr.(*dns.SOA).Mbox)

			ctx.soa = rr.(*dns.SOA)
			// UPDATING THE SERIAL
			if updateSerial {
				todayInt, _ := strconv.Atoi(time.Now().Format("20060102"))
				if ctx.soa.Serial/100 < uint32(todayInt) { // Only if current serial number is less than today date
					// we set serial as today's YYYYMMDD00
					ctx.soa.Serial = uint32(todayInt) * 100
				} else {
					ctx.soa.Serial += 2
				}
			}

			// Getting zone name if it is not defined as argument
			if ctx.Config.Zone == "" {
				ctx.Config.Zone = strings.ToLower(rr.Header().Name)
			}
		case dns.TypeZONEMD:
			zoneMDMap[rr.(*dns.ZONEMD).Hash] = rr.(*dns.ZONEMD)
		case dns.TypeNS:
			// I hate you RFC 4034, Section 6.2
			rr.(*dns.NS).Ns = strings.ToLower(rr.(*dns.NS).Ns)

			// Add to delegated if it applies
			if rr.Header().Name != ctx.Config.Zone {
				delegatedZones[rr.Header().Name] = struct{}{}
			}
		case dns.TypeDNSKEY:
			key := rr.(*dns.DNSKEY)
			switch key.Flags {
			case 256:
				ctx.DNSKEYS.ZSK[key.KeyTag()] = key
			case 257:
				ctx.DNSKEYS.KSK[key.KeyTag()] = key
			}
		case dns.TypeDS:
			ctx.WithDS[rr.Header().Name] = struct{}{}
		case dns.TypeMD:
			rr.(*dns.MD).Md = strings.ToLower(rr.(*dns.MD).Md)
		case dns.TypeMF:
			rr.(*dns.MF).Mf = strings.ToLower(rr.(*dns.MF).Mf)
		case dns.TypeCNAME:
			rr.(*dns.CNAME).Target = strings.ToLower(rr.(*dns.CNAME).Target)
		case dns.TypeMB:
			rr.(*dns.MB).Mb = strings.ToLower(rr.(*dns.MB).Mb)
		case dns.TypeMR:
			rr.(*dns.MR).Mr = strings.ToLower(rr.(*dns.MR).Mr)
		case dns.TypePTR:
			rr.(*dns.PTR).Ptr = strings.ToLower(rr.(*dns.PTR).Ptr)
		case dns.TypeMINFO:
			rr.(*dns.MINFO).Rmail = strings.ToLower(rr.(*dns.MINFO).Rmail)
			rr.(*dns.MINFO).Email = strings.ToLower(rr.(*dns.MINFO).Email)
		case dns.TypeMX:
			rr.(*dns.MX).Mx = strings.ToLower(rr.(*dns.MX).Mx)
		case dns.TypeRP:
			rr.(*dns.RP).Mbox = strings.ToLower(rr.(*dns.RP).Mbox)
			rr.(*dns.RP).Txt = strings.ToLower(rr.(*dns.RP).Txt)
		case dns.TypeAFSDB:
			rr.(*dns.AFSDB).Hostname = strings.ToLower(rr.(*dns.AFSDB).Hostname)
		case dns.TypeRT:
			rr.(*dns.RT).Host = strings.ToLower(rr.(*dns.RT).Host)
		case dns.TypeSIG:
			rr.(*dns.SIG).SignerName = strings.ToLower(rr.(*dns.SIG).SignerName)
		case dns.TypeRRSIG:
			rr.(*dns.RRSIG).SignerName = strings.ToLower(rr.(*dns.RRSIG).SignerName)
		case dns.TypePX:
			rr.(*dns.PX).Map822 = strings.ToLower(rr.(*dns.PX).Map822)
			rr.(*dns.PX).Mapx400 = strings.ToLower(rr.(*dns.PX).Mapx400)
		case dns.TypeNAPTR:
			rr.(*dns.NAPTR).Replacement = strings.ToLower(rr.(*dns.NAPTR).Replacement)
		case dns.TypeKX:
			rr.(*dns.KX).Exchanger = strings.ToLower(rr.(*dns.KX).Exchanger)
		case dns.TypeSRV:
			rr.(*dns.SRV).Target = strings.ToLower(rr.(*dns.SRV).Target)
		case dns.TypeDNAME:
			rr.(*dns.DNAME).Target = strings.ToLower(rr.(*dns.DNAME).Target)
		case dns.TypeNSEC:
			rr.(*dns.NSEC).NextDomain = strings.ToLower(rr.(*dns.NSEC).NextDomain)
		}
		// Skipping non-zone rrs
		if dns.IsSubDomain(ctx.Config.Zone, rr.Header().Name) {
			rrs = append(rrs, rr)
		}
	}
	if zone.Err() != nil {
		return fmt.Errorf("error parsing zone: %s", zone.Err())
	}
	if ctx.soa == nil {
		return fmt.Errorf("SOA RR not found")
	}
	if ctx.Config.Zone == "" {
		return fmt.Errorf("zone name not defined in arguments nor guessable using SOA RR. Try again using --zone argument")
	}

	var wg sync.WaitGroup

	zonemdChan := make(chan *dns.ZONEMD)
	errorChan := make(chan error)
	// We look for the correct zonemd RRs
	for _, newmd := range zoneMDMap {
		wg.Add(1)
		go func(newmd *dns.ZONEMD) {
			defer wg.Done()
			if newmd.Header().Name == ctx.Config.Zone && (newmd.Scheme == 1) && (newmd.Hash == 1 || newmd.Hash == 2) {
				if ctx.isZONEMDAlready(newmd) {
					errorChan <- fmt.Errorf("two ZONEMD with same Scheme and configured Hash found in zone")
					return
				} else {
					zonemdChan <- newmd
				}
			}
		}(newmd)
	}
	go func() {
		wg.Wait()
		close(zonemdChan)
		close(errorChan)
	}()
	for md := range zonemdChan {
		ctx.zonemdMap[md.Hash] = md
	}
	for e := range errorChan {
		return e
	}
	ctx.rrs = rrs
	ctx.DelegatedZones = delegatedZones
	return nil
}

// AddNSEC13 adds NSEC 1 and 3 rrs to the RR list.
func (ctx *Context) AddNSEC13() {
	if ctx.Config.NSEC3 {
		errors := 0
		for {
			if err := ctx.addNSEC3Records(); err != nil {
				ctx.Log.Printf("%s", err)
				errors++
				if errors == 3 {
					panic("cannot add NSEC3 Records. Chech your --nsec3-* params and try again.")
				}
			} else {
				break
			}
		}
	} else {
		ctx.addNSECRecords()
	}
}

// NewPKCS11Session creates a new session.
// The arguments also define the HSM user key and the pkcs11 label the keys will use when created or retrieved.
func (ctx *Context) NewPKCS11Session(key, label, p11lib string) (SignSession, error) {
	p := pkcs11.New(p11lib)
	if p == nil {
		return nil, fmt.Errorf("error initializing %s: file not found", p11lib)
	}
	err := p.Initialize()
	if err != nil {
		return nil, fmt.Errorf("error initializing %s: %s. (Has the .db RW permission?)", p11lib, err)
	}
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("error checking slots: %s", err)
	}
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("error creating session: %s", err)
	}
	err = p.Login(session, pkcs11.CKU_USER, key)
	if err != nil {
		return nil, fmt.Errorf("error login with provided key: %s", err)
	}
	return &PKCS11Session{
		libPath:    p11lib,
		ctx:        ctx,
		P11Context: p,
		Handle:     session,
		Key:        key,
		Label:      label,
	}, nil
}

// NewFileSession creates a new File session.
// The arguments define the readers for the zone signing and key signing keys.
func (ctx *Context) NewFileSession(zsk, ksk io.ReadWriteSeeker) (SignSession, error) {
	return &FileSession{
		ctx:     ctx,
		kskFile: ksk,
		zskFile: zsk,
	}, nil
}

// Close closes the output file if it is defined.
func (ctx *Context) Close() error {
	if ctx.Output != nil {
		err := ctx.Output.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Returns a signing/digesting info string with the library name and signing mode
func (ctx *Context) genInfo(session SignSession) string {
	now := time.Now().Unix()
	switch s := session.(type) {
	case *PKCS11Session:
		return fmt.Sprintf("signer=dns-tools;timestamp=%d;mode=pkcs11;libname=%s;", now, path.Base(s.libPath))
	case *FileSession:
		return fmt.Sprintf("signer=dns-tools;timestamp=%d;mode=file;", now)
	}
	// I assume that no session implies digest mode
	return fmt.Sprintf("signer=dns-tools;timestamp=%d;mode=digest", now)
}

// isDelegated returns true if the rr requires to be signed.
// The design of DNSSEC stipulates that delegations (non-apex NS records)
// are not signed, and neither are any glue records.
func (ctx *Context) isDelegated(ownerName string) bool {
	splitDomain := dns.SplitDomainName(dns.Fqdn(ownerName))
	for i := 0; i < len(splitDomain); i++ {
		domain := strings.Join(splitDomain[i:], ".")
		if _, ok := ctx.DelegatedZones[domain]; ok {
			return true
		}
	}
	return false
}

// CreateNewDNSKEY creates a new DNSKEY RR, using the parameters provided.
func (ctx *Context) CreateNewDNSKEY(flags uint16, publicKey string) *dns.DNSKEY {
	dnskey := &dns.DNSKEY{
		Flags:     flags,
		Protocol:  3, // RFC4034 2.1.2
		Algorithm: uint8(ctx.SignAlgorithm),
		Hdr: dns.RR_Header{
			Name:   ctx.Config.Zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    ctx.soa.Minttl,
		},
		PublicKey: publicKey,
	}
	if flags == 256 {
		ctx.DNSKEYS.ZSK[dnskey.KeyTag()] = dnskey
	} else if flags == 257 {
		ctx.DNSKEYS.KSK[dnskey.KeyTag()] = dnskey
	}
	return dnskey
}

// PrintDS prints to log device DS value of zone:
func (ctx *Context) PrintDS() {
	var wg sync.WaitGroup
	for _, key := range ctx.DNSKEYS.KSK {
		wg.Add(1)
		go func(k *dns.DNSKEY) {
			defer wg.Done()
			ds := k.ToDS(dns.SHA256)
			ctx.Log.Printf("DS[Tag %d]:\"%s\"", k.KeyTag(), ds)
		}(key)
	}
	wg.Wait()
}
