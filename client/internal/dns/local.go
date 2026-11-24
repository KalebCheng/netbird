package dns

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
)

type registrationMap map[string]struct{}

type localResolver struct {
	registeredMap registrationMap
	records       sync.Map
}

func (d *localResolver) stop() {
}

// ServeDNS handles a DNS request
func (d *localResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Tracef("received question: %#v", r.Question[0])
	replyMessage := &dns.Msg{}
	replyMessage.SetReply(r)
	replyMessage.RecursionAvailable = true
	replyMessage.Rcode = dns.RcodeSuccess

	responses := d.lookupRecords(r)
	if len(responses) > 0 {
		replyMessage.Answer = append(replyMessage.Answer, responses...)
	}

	err := w.WriteMsg(replyMessage)
	if err != nil {
		log.Debugf("got an error while writing the local resolver response, error: %v", err)
	}
}

func (d *localResolver) lookupRecords(r *dns.Msg) []dns.RR {
	question := r.Question[0]
	if record, found := d.lookupRecord(question.Name, question.Qclass, question.Qtype); found {
		return []dns.RR{record}
	}

	// A/AAAA lookups must include the CNAME chain. The NetBird DNS config
	// can contain only a CNAME for a managed domain; returning NODATA makes
	// macOS treat the name as nonexistent instead of following the target.
	if question.Qtype == dns.TypeCNAME {
		return nil
	}
	record, found := d.lookupRecord(question.Name, question.Qclass, dns.TypeCNAME)
	if !found {
		return nil
	}

	responses := []dns.RR{record}
	target := record.(*dns.CNAME).Target
	for i := 0; i < 8; i++ {
		if answer, found := d.lookupRecord(target, question.Qclass, question.Qtype); found {
			responses = append(responses, answer)
			break
		}
		next, found := d.lookupRecord(target, question.Qclass, dns.TypeCNAME)
		if !found {
			break
		}
		responses = append(responses, next)
		target = next.(*dns.CNAME).Target
	}
	return responses
}

func (d *localResolver) lookupRecord(name string, class, qType uint16) (dns.RR, bool) {
	record, found := d.records.Load(buildRecordKey(dns.Fqdn(name), class, qType))
	if !found {
		return nil, false
	}
	return record.(dns.RR), true
}

func (d *localResolver) registerRecord(record nbdns.SimpleRecord) error {
	fullRecord, err := dns.NewRR(record.String())
	if err != nil {
		return err
	}

	fullRecord.Header().Rdlength = record.Len()

	header := fullRecord.Header()
	d.records.Store(buildRecordKey(header.Name, header.Class, header.Rrtype), fullRecord)

	return nil
}

func (d *localResolver) deleteRecord(recordKey string) {
	d.records.Delete(dns.Fqdn(recordKey))
}

func buildRecordKey(name string, class, qType uint16) string {
	key := fmt.Sprintf("%s_%d_%d", name, class, qType)
	return key
}
