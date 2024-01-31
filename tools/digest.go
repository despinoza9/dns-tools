package tools

/* leer la zona
   agregar DigestEnabled con 00s de digest
   ordenar zona
   firmar zona
   update DigestEnabled
   recalcular RRSIG de DigestEnabled y actualizar (o agregar?)
   recalcular DS?
   ojo que SOA y DigestEnabled deben ser el mismo en la zona a publicar */

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"runtime"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

var intToHash = map[uint8]func() hash.Hash{
	0: sha512.New384, // Default is the same hash as 1
	1: sha512.New384,
	2: sha512.New,
}

// ValidationResult contains results obtained in VerifyDigest
type ValidationResult struct {
	MDRecord *dns.ZONEMD
	Error    error
}

// VerifyDigest validates a version of a zone with a valid ZONEMD RR.
func (ctx *Context) VerifyDigest() error {

	ctx.Log.Printf("Verifying ZONEMD digests")
	if ctx.File == nil {
		return fmt.Errorf("zone file not defined")
	}
	if ctx.Log == nil {
		return fmt.Errorf("log not defined")
	}

	if err := ctx.ReadAndParseZone(false); err != nil {
		return err
	}
	if ctx.zonemdMap == nil {
		return fmt.Errorf("cannot verify (ZONEMD RR not present)")
	}
	for _, mdRR := range ctx.zonemdMap {
		if ctx.soa.Serial != mdRR.Serial {
			return fmt.Errorf("ZONEMD serial does not match with SOA serial")
		}
	}
	ctx.Log.Printf("Sorting zone")
	quickSort(ctx.rrs)
	ctx.Log.Printf("Zone sorted")

	results := make(chan ValidationResult, len(ctx.zonemdMap))
	var wg sync.WaitGroup
	for _, mdRR := range ctx.zonemdMap {
		wg.Add(1)
		go func(mdRR *dns.ZONEMD) {
			defer wg.Done()
			ctx.Log.Printf("Checking ZONEMD %s with "+
				"scheme %d and hashAlg %d", mdRR.Header().Name,
				mdRR.Scheme, mdRR.Hash)
			err := ctx.ValidateOrderedZoneDigest(mdRR.
				Hash, mdRR.Digest)
			results <- ValidationResult{MDRecord: mdRR,
				Error: err}
		}(mdRR)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for i := 0; i < len(ctx.zonemdMap); i++ {
		result := <-results
		if result.Error != nil {
			return result.Error
		}
		ctx.Log.Printf("ZONEMD %s is valid!", result.
			MDRecord.Header().Name)
	}
	return nil
}

// Digest creates a version of a zone with a valid ZONEMD RR.
func (ctx *Context) Digest() error {
	if ctx.File == nil {
		return fmt.Errorf("zone file not defined")
	}
	if ctx.Output == nil {
		return fmt.Errorf("output not defined")
	}
	if ctx.Log == nil {
		return fmt.Errorf("log not defined")
	}

	if err := ctx.ReadAndParseZone(false); err != nil {
		return err
	}
	ctx.Log.Printf("Sorting zone")
	quickSort(ctx.rrs)
	ctx.Log.Printf("Zone Sorted")

	if err := ctx.UpdateDigest(); err != nil {
		return err
	}
	// Write digest to out
	if err := ctx.WriteZone(); err != nil {
		return err
	}
	return nil
}

// AddZONEMDRecord adds a zone digest following draft-ietf-dnsop-dns-zone-digest-05
// we need the SOA info for that
func (ctx *Context) AddZONEMDRecord() {
	_, exists := ctx.zonemdMap[ctx.Config.HashAlg]
	if !exists {
		zonemd := &dns.ZONEMD{
			Hdr: dns.RR_Header{
				Name:   ctx.soa.Header().Name,
				Rrtype: dns.TypeZONEMD,
				Class:  dns.ClassINET,
				Ttl:    ctx.soa.Header().Ttl,
			},
			Serial: ctx.soa.Serial,
			Scheme: 1, // SIMPLE
			Hash:   ctx.Config.HashAlg,
			Digest: strings.Repeat("00", 48),
		}
		ctx.rrs = append(ctx.rrs, zonemd)
		ctx.zonemdMap[zonemd.Hash] = zonemd
	}
}

// CleanDigests sets all root zone digests to 0
// It is used before zone signing
func (ctx *Context) CleanDigests() {
	var wg sync.WaitGroup
	n := len(ctx.rrs)
	numSegments := runtime.NumCPU()
	segmentSize := (n + numSegments - 1) / numSegments

	for i := 0; i < len(ctx.rrs); i += segmentSize {
		wg.Add(1)
		go func(records []dns.RR) {
			defer wg.Done()
			for _, rr := range records {
				if x, ok := rr.(*dns.ZONEMD); ok {
					x.Digest = strings.Repeat("0", len(x.Digest))
				}
			}
		}(ctx.rrs[i:minimum(i+segmentSize, len(ctx.rrs))])
	}
	wg.Wait()
}

// Obtains the minimum between two values
func minimum(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CalculateDigest calculates the digest for a PREVIOUSLY ORDERED zone.
// This method returns the digest hex value.
func (ctx *Context) CalculateDigest(hashAlg uint8) (string, error) {
	if ctx.zonemdMap == nil {
		return "", fmt.Errorf("error trying to calculate a digest without a ZONEMD RR present")
	}
	ctx.Log.Print("Started digest calculation.")
	hashFunc, ok := intToHash[hashAlg]
	if !ok {
		return "", fmt.Errorf("hashAlg provided (%d) is not valid", hashAlg)
	}
	h := hashFunc()
	BufferLength := 1024 * 1024 // 1 MB is very reasonable imho.
	buf := make([]byte, BufferLength)
	lastPos := 0
	var prevRR dns.RR
	for _, rr := range ctx.rrs {
		switch {
		// Ignore ZONEMD RRs (new in v06)
		case rr.Header().Rrtype == dns.TypeZONEMD && rr.Header().Name == ctx.Config.Zone:
			continue
		// Ignore duplicate RRs
		case prevRR != nil && dns.IsDuplicate(prevRR, rr):
			continue
			// 3.4 Inclusions/Exclusions
			// The RRSIG covering ZONEMD MUST NOT be included because the RRSIG
			// will be updated after all digests have been calculated.
		case rr.Header().Rrtype == dns.TypeRRSIG &&
			rr.(*dns.RRSIG).TypeCovered == dns.TypeZONEMD:
			continue
		}
		newPos, err := dns.PackRR(rr, buf, lastPos, nil, false)
		if err != nil || newPos > BufferLength {
			if newPos > BufferLength || err == dns.ErrRdata || err == dns.ErrBuf || strings.Contains(err.Error(), "overflow") {
				h.Write(buf[:lastPos])
				buf = make([]byte, BufferLength)
				newPos, err = dns.PackRR(rr, buf, 0, nil, false)
				if err != nil {
					return "", err
				}
			} else {
				return "", err
			}
		}
		lastPos = newPos
		prevRR = rr
	}
	h.Write(buf[:lastPos])
	ctx.Log.Print("Stopped digest calculation.")
	digest := hex.EncodeToString(h.Sum(nil))
	return digest, nil
}

// UpdateDigest calculates the digest for a PREVIOUSLY ORDERED zone with one ZONEMD RR
// This method updates the ZONEMD RR directly
func (ctx *Context) UpdateDigest() (err error) {
	ctx.Log.Printf("Updating ZONEMD Digest")
	zonemd, found := ctx.zonemdMap[ctx.Config.HashAlg]
	if !found {
		zonemd = &dns.ZONEMD{
			Hdr: dns.RR_Header{
				Name:   ctx.soa.Header().Name,
				Rrtype: dns.TypeZONEMD,
				Class:  dns.ClassINET,
				Ttl:    ctx.soa.Header().Ttl,
			},
			Serial: ctx.soa.Serial,
			Scheme: 1, // SIMPLE
			Hash:   ctx.Config.HashAlg,
			Digest: strings.Repeat("00", 48),
		}
		// Agregar al mapa
		ctx.zonemdMap[ctx.Config.HashAlg] = zonemd
	}
	// Calcular el digest
	digest, err :=
		ctx.CalculateDigest(zonemd.Hash)
	if err != nil {
		return
	}
	zonemd.Digest = digest
	zonemd.Serial = ctx.soa.Serial
	return nil
}

// ValidateOrderedZoneDigest validates the digest for a PREVIOUSLY ORDERED zone.
// Returns nil if the calculated digest is equals the ZONEMD one, and an error otherwise.
// Follows the validation from https://datatracker.ietf.org/doc/draft-ietf-dnsop-dns-zone-digest.
// It is hardcoded to use SIMPLE scheme.
func (ctx *Context) ValidateOrderedZoneDigest(hashAlg uint8, mddigest string) error {
	digest, err := ctx.CalculateDigest(hashAlg)
	if err != nil {
		return err
	}
	if !strings.EqualFold(digest, mddigest) {
		return fmt.Errorf("invalid digest\n   expected: %s\n   obtained: %s", mddigest, digest)
	}
	return nil
}
