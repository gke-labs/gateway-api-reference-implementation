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
	"bytes"
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

func parseCompressedPTR(t *testing.T, target string) (dnsmessage.Resource, []byte) {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	builder.EnableCompression()
	startQuestionsErr := builder.StartQuestions()
	if startQuestionsErr != nil {
		t.Fatalf("starting questions: %v", startQuestionsErr)
	}
	questionErr := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(target),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	})
	if questionErr != nil {
		t.Fatalf("adding question: %v", questionErr)
	}
	startAnswersErr := builder.StartAnswers()
	if startAnswersErr != nil {
		t.Fatalf("starting answers: %v", startAnswersErr)
	}
	record := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypePTR, 120, &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(target)})
	appendErr := appendResource(&builder, record)
	if appendErr != nil {
		t.Fatalf("appending record: %v", appendErr)
	}
	packedMessage, finishErr := builder.Finish()
	if finishErr != nil {
		t.Fatalf("finishing compressed message: %v", finishErr)
	}

	var parser dnsmessage.Parser
	header, startErr := parser.Start(packedMessage)
	if startErr != nil {
		t.Fatalf("starting parser: %v", startErr)
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("unexpected rcode: %v", header.RCode)
	}
	skipErr := parser.SkipAllQuestions()
	if skipErr != nil {
		t.Fatalf("skipping questions: %v", skipErr)
	}
	parsedHeader, headerErr := parser.AnswerHeader()
	if headerErr != nil {
		t.Fatalf("reading answer header: %v", headerErr)
	}
	if parsedHeader.Type != dnsmessage.TypePTR {
		t.Fatalf("unexpected header type: %v", parsedHeader.Type)
	}
	unknownResource, unknownErr := parser.UnknownResource()
	if unknownErr != nil {
		t.Fatalf("reading unknown resource: %v", unknownErr)
	}

	var typedParser dnsmessage.Parser
	typedHeader, startTypedErr := typedParser.Start(packedMessage)
	if startTypedErr != nil {
		t.Fatalf("starting typed parser: %v", startTypedErr)
	}
	if typedHeader.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("unexpected rcode: %v", typedHeader.RCode)
	}
	skipTypedErr := typedParser.SkipAllQuestions()
	if skipTypedErr != nil {
		t.Fatalf("skipping questions: %v", skipTypedErr)
	}
	parsedRecord, answerErr := typedParser.Answer()
	if answerErr != nil {
		t.Fatalf("parsing answer: %v", answerErr)
	}
	return parsedRecord, unknownResource.Data
}

func TestProbeTieBreak(t *testing.T) {
	recordClass1 := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordClass2 := makeTestResource(dnsmessage.Class(2), dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordCacheFlush := makeTestResource(dnsmessage.Class(uint16(dnsmessage.ClassINET)|CacheFlushBit), dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordTypeAAAA := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeAAAA, 120, &dnsmessage.AAAAResource{AAAA: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
	recordRData99 := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{169, 254, 99, 200}})
	recordRData200 := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{169, 254, 200, 50}})
	recordDiffTTL := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypeA, 300, &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}})
	recordPtrB := makeTestResource(dnsmessage.ClassINET, dnsmessage.TypePTR, 120, &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("b.local.")})

	compressedPtrA, compressedBytesA := parseCompressedPTR(t, "a.local.")

	// Verify that wire-compressed "a.local." RDATA (pointer 0xC0...) compares greater than
	// uncompressed "b.local." RDATA (0x01...), proving that wire compression gives the opposite result.
	uncompressedBytesB, _, extractErr := uncompressedRData(recordPtrB)
	if extractErr != nil {
		t.Fatalf("extracting uncompressed rdata for recordPtrB: %v", extractErr)
	}
	if bytes.Compare(compressedBytesA, uncompressedBytesB) <= 0 {
		t.Fatalf("expected compressed bytes to compare greater than uncompressed bytes")
	}

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
			name:     "name compression does not affect canonical result",
			opponent: []dnsmessage.Resource{compressedPtrA},
			ours:     []dnsmessage.Resource{recordPtrB},
			want:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, compareErr := isLexicographicallyGreater(test.opponent, test.ours)
			if compareErr != nil {
				t.Fatalf("unexpected comparison error: %v", compareErr)
			}
			if got != test.want {
				t.Fatalf("isLexicographicallyGreater() = %v, want %v", got, test.want)
			}
		})
	}
}
