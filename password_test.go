package password

import "testing"

var target Algorithm

func TestNewAlgo(t *testing.T) {
	want := MD5{}

	target, _ = NewAlgo("md5")

	if target != want {
		t.Fail()
	}
}

func TestMD5_Encode(t *testing.T) {
	want := "21232f297a57a5a743894a0e4a801fc3"

	result, _ := target.Encode("admin")

	if result != want {
		t.Fail()
	}
}

func TestMD5_Verify(t *testing.T) {
	hash := "21232f297a57a5a743894a0e4a801fc3"

	result, _ := target.Verify("admin", hash)

	if result != true {
		t.Fail()
	}
}
