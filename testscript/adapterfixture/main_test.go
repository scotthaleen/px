package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIndependentVersionOneCommandGolden(t *testing.T) {
	commandID := "018bcfe5-6800-7000-8000-000000000001"
	enrollmentID := strings.Repeat("f", 32)
	settled := "2023-11-14T22:13:20Z"
	deviceID := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	golden := `{"version":1,"schema_version":1,"action":"enrollment.approve","command_id":"` + commandID + `","enrollment_id":"` + enrollmentID + `","state":"committed","admitted_at":"` + settled + `","settled_at":"` + settled + `","result":{"enrollment_id":"` + enrollmentID + `","device_id":"` + deviceID + `","label":"fixture","revision":1}}`
	var result command
	if err := strictDecode([]byte(golden), &result); err != nil || !validCommand(result, commandID, enrollmentID) {
		t.Fatalf("golden command = %+v, %v", result, err)
	}
	for _, malformed := range []string{
		strings.Replace(golden, `"state":"committed"`, `"state":"unknown"`, 1),
		strings.Replace(golden, `,"result":`, `,"unknown":true,"result":`, 1),
		strings.Replace(golden, commandID, "018bcfe5-6800-7000-8000-000000000002", 1),
		strings.Replace(golden, `"revision":1`, `"revision":0`, 1),
	} {
		var decoded command
		if err := strictDecode([]byte(malformed), &decoded); err == nil && validCommand(decoded, commandID, enrollmentID) {
			t.Fatalf("malformed command accepted: %s", malformed)
		}
	}
}

func TestIndependentStrictWirePresenceRejectsOmittedAndNull(t *testing.T) {
	deviceID := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	enrollmentID := strings.Repeat("f", 32)
	commandID := "018bcfe5-6800-7000-8000-000000000001"
	validTime := "2023-11-14T22:13:20Z"
	tests := []struct {
		name   string
		data   string
		output func() any
	}{
		{name: "page floor omitted", data: `{"version":1,"high_water":0,"facts":[]}`, output: func() any { return &factPage{} }},
		{name: "page high water null", data: `{"version":1,"floor":0,"high_water":null,"facts":[]}`, output: func() any { return &factPage{} }},
		{name: "fact seq omitted", data: fmt.Sprintf(`{"version":1,"floor":0,"high_water":1,"facts":[{"kind":"enrollment.pending_expired","enrollment_id":"%s","occurred_at":"%s","device_id":"%s","label":"fixture"}]}`, enrollmentID, validTime, deviceID), output: func() any { return &factPage{} }},
		{name: "fact timestamp null", data: fmt.Sprintf(`{"version":1,"floor":0,"high_water":1,"facts":[{"seq":1,"kind":"enrollment.pending_expired","enrollment_id":"%s","occurred_at":null,"device_id":"%s","label":"fixture"}]}`, enrollmentID, deviceID), output: func() any { return &factPage{} }},
		{name: "optional revision null", data: fmt.Sprintf(`{"version":1,"floor":0,"high_water":1,"facts":[{"seq":1,"kind":"enrollment.member_approved","enrollment_id":"%s","occurred_at":"%s","device_id":"%s","label":"fixture","member_revision":null}]}`, enrollmentID, validTime, deviceID), output: func() any { return &factPage{} }},
		{name: "pending high water omitted", data: `{"version":1,"pending":[]}`, output: func() any { return &pendingSnapshot{} }},
		{name: "pending timestamp null", data: fmt.Sprintf(`{"version":1,"high_water":1,"pending":[{"enrollment_id":"%s","device_id":"%s","label":"fixture","created_at":null,"expires_at":"%s"}]}`, enrollmentID, deviceID, validTime), output: func() any { return &pendingSnapshot{} }},
		{name: "command admitted timestamp omitted", data: fmt.Sprintf(`{"version":1,"schema_version":1,"action":"enrollment.approve","command_id":"%s","enrollment_id":"%s","state":"admitted"}`, commandID, enrollmentID), output: func() any { return &command{} }},
		{name: "command settlement null", data: fmt.Sprintf(`{"version":1,"schema_version":1,"action":"enrollment.approve","command_id":"%s","enrollment_id":"%s","state":"committed","admitted_at":"%s","settled_at":null}`, commandID, enrollmentID, validTime), output: func() any { return &command{} }},
		{name: "result revision omitted", data: fmt.Sprintf(`{"version":1,"schema_version":1,"action":"enrollment.approve","command_id":"%s","enrollment_id":"%s","state":"committed","admitted_at":"%s","settled_at":"%s","result":{"enrollment_id":"%s","device_id":"%s","label":"fixture"}}`, commandID, enrollmentID, validTime, validTime, enrollmentID, deviceID), output: func() any { return &command{} }},
		{name: "error version omitted", data: `{"code":"invalid_request","message":"invalid"}`, output: func() any { return &apiError{} }},
		{name: "error message null", data: `{"version":1,"code":"invalid_request","message":null}`, output: func() any { return &apiError{} }},
		{name: "cursor error floor omitted", data: `{"version":1,"code":"cursor_expired","message":"expired","high_water":1}`, output: func() any { return &apiError{} }},
		{name: "unknown outcome command null", data: `{"version":1,"code":"outcome_unknown","message":"unknown","command_id":null}`, output: func() any { return &apiError{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := strictDecode([]byte(test.data), test.output()); err == nil {
				t.Fatalf("malformed wire value accepted: %s", test.data)
			}
		})
	}
	for _, valid := range []struct {
		data   string
		output any
	}{
		{data: `{"version":1,"floor":0,"high_water":0,"facts":[]}`, output: &factPage{}},
		{data: `{"version":1,"high_water":0,"pending":[]}`, output: &pendingSnapshot{}},
		{data: `{"version":1,"code":"cursor_expired","message":"expired","floor":0,"high_water":0}`, output: &apiError{}},
	} {
		if err := strictDecode([]byte(valid.data), valid.output); err != nil {
			t.Fatalf("present zero value rejected: %s: %v", valid.data, err)
		}
	}
}

func TestIndependentUUIDv7MonotonicAcrossRollback(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_123)
	first, err := nextUUIDv7("", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := nextUUIDv7(first, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !commandIDPattern.MatchString(first) || !commandIDPattern.MatchString(second) || second <= first {
		t.Fatalf("UUIDv7 sequence = %q, %q", first, second)
	}
}
