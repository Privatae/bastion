//go:build darwin

package main

import "testing"

func TestParseSystemProfiler(t *testing.T) {
	raw := []byte(`{"SPApplicationsDataType":[
	 {"_name":"Autodesk Fusion 360","version":"2.0.19","path":"/Users/u/Applications/Autodesk Fusion 360.app",
	  "obtained_from":"identified_developer","signed_by":["Developer ID Application: Autodesk, Inc. (XYZ123)","Apple Root CA"]},
	 {"_name":"Safari","version":"18.0","path":"/System/Applications/Safari.app","obtained_from":"apple"},
	 {"_name":"Blender","version":"4.2","path":"/Applications/Blender.app","obtained_from":"identified_developer"}]}`)
	apps, err := parseSystemProfiler(raw)
	if err != nil || len(apps) != 2 {
		t.Fatalf("two non-Apple apps: %v %+v", err, apps)
	}
	if apps[0].Publisher != "Autodesk, Inc." || apps[0].Version != "2.0.19" || apps[0].Source != "applications" {
		t.Fatalf("fusion: %+v", apps[0])
	}
	if apps[1].Publisher != "" {
		t.Fatalf("no signer → no publisher: %+v", apps[1])
	}
}

func TestParseSystemEventsWindows(t *testing.T) {
	out := "4242\tFusion 360\ttrue\tflowerpot v3\n" +
		"77\tFinder\tfalse\tDocuments\n" +
		"77\tFinder\tfalse\t\n" + // untitled window skipped
		"bad line\n"
	wins := parseSystemEventsWindows(out)
	if len(wins) != 2 || !wins[0].Focused || wins[0].PID != 4242 || wins[0].App != "Fusion 360" {
		t.Fatalf("%+v", wins)
	}
	if wins[1].Focused || wins[1].Title != "Documents" {
		t.Fatalf("%+v", wins[1])
	}
}
