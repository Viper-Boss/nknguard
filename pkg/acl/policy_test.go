package acl

import "testing"

func TestDefaultDenyAndFirstMatch(t *testing.T) {
	laptop := Subject{DeviceID: "nkg_l", Name: "laptop", Tags: []string{"admin"}}
	nas := Subject{DeviceID: "nkg_n", Name: "nas-home"}
	phone := Subject{DeviceID: "nkg_p", Name: "phone"}
	policy := Policy{Default: Deny, Rules: []Rule{
		{Source: "phone", Destination: "nas-home", Action: Deny},
		{Source: "tag:admin", Destination: "*", Action: Allow},
		{Source: "*", Destination: "nas-home", Action: Allow},
	}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	if !policy.Permits(laptop, nas) {
		t.Fatal("tagged admin denied")
	}
	if policy.Permits(phone, nas) {
		t.Fatal("first matching deny ignored")
	}
	if policy.Permits(nas, phone) {
		t.Fatal("unmatched pair allowed under default deny")
	}
	if DefaultPolicy().Permits(laptop, nas) {
		t.Fatal("default policy is not deny")
	}
}

func TestValidateRejectsAmbiguity(t *testing.T) {
	if (Policy{Default: "maybe"}).Validate() == nil {
		t.Fatal("unknown default accepted")
	}
	if (Policy{Default: Deny, Rules: []Rule{{Source: "", Destination: "*", Action: Allow}}}).Validate() == nil {
		t.Fatal("empty selector accepted")
	}
}
