// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mdns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func makeTestResource(class dnsmessage.Class, recordType dnsmessage.Type, ttl uint32, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("test.local."),
			Type:  recordType,
			Class: class,
			TTL:   ttl,
		},
		Body: body,
	}
}

func TestProbeTieBreak(t *testing.T) {
	recordClass1 := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordClass2 := makeTestResource(dnsmessage.Class(2), dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordCacheFlush := makeTestResource(dnsmessage.Class(uint16(dnsmessage.ClassINET)|CacheFlushBit), dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordTypeAAAA := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeAAAA, 120, &dnsmessage.AAAAResource{AAAA: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
	recordRData99 := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{169, 254, 99, 200}})
	recordRData200 := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{169, 254, 200, 50}})
	recordDiffTTL := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 300, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordOtherType := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypePTR, 120, &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("target.local.")})

	tests := []struct {
		name     string
		opponent []dnsmessage.Resource
		ours     []dnsmessage.Resource
		want     bool
	}{
		{
			name:     "lower class loses",
			opponent: []dnsmessage.Resource{recordClass1},
			ours:     []dnsmessage.Resource{recordClass2},
			want:     false,
		},
		{
			name:     "higher class wins",
			opponent: []dnsmessage.Resource{recordClass2},
			ours:     []dnsmessage.Resource{recordClass1},
			want:     true,
		},
		{
			name:     "cache-flush bit cleared in class",
			opponent: []dnsmessage.Resource{recordCacheFlush},
			ours:     []dnsmessage.Resource{recordClass1},
			want:     false,
		},
		{
			name:     "lower type loses",
			opponent: []dnsmessage.Resource{recordClass1},
			ours:     []dnsmessage.Resource{recordTypeAAAA},
			want:     false,
		},
		{
			name:     "higher type wins",
			opponent: []dnsmessage.Resource{recordTypeAAAA},
			ours:     []dnsmessage.Resource{recordClass1},
			want:     true,
		},
		{
			name:     "rdata compared byte by byte unsigned",
			opponent: []dnsmessage.Resource{recordRData200},
			ours:     []dnsmessage.Resource{recordRData99},
			want:     true,
		},
		{
			name:     "identical record sets tie",
			opponent: []dnsmessage.Resource{recordClass1},
			ours:     []dnsmessage.Resource{recordClass1},
			want:     false,
		},
		{
			name:     "ttl ignored in comparison",
			opponent: []dnsmessage.Resource{recordClass1},
			ours:     []dnsmessage.Resource{recordDiffTTL},
			want:     false,
		},
		{
			name:     "multiple records sorted into order",
			opponent: []dnsmessage.Resource{recordTypeAAAA, recordClass1},
			ours:     []dnsmessage.Resource{recordClass1, recordTypeAAAA},
			want:     false,
		},
		{
			name:     "records remaining wins",
			opponent: []dnsmessage.Resource{recordClass1, recordTypeAAAA},
			ours:     []dnsmessage.Resource{recordClass1},
			want:     true,
		},
		{
			name:     "records remaining loses",
			opponent: []dnsmessage.Resource{recordClass1},
			ours:     []dnsmessage.Resource{recordClass1, recordTypeAAAA},
			want:     false,
		},
		{
			name:     "other record type in opponent probe treats opponent as winner",
			opponent: []dnsmessage.Resource{recordOtherType},
			ours:     []dnsmessage.Resource{recordClass1},
			want:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isLexicographicallyGreater(test.opponent, test.ours)
			if got != test.want {
				t.Fatalf("isLexicographicallyGreater() = %v, want %v", got, test.want)
			}
		})
	}
}
