//go:build !windows

package main

// uipopup_other.go — off Windows there is no tray to open the approvals popup
// from (tray_windows.go says why), so the page opens in the default browser,
// the same way `privatae-bastion ui` opens the front page.
func openPopupWindow(url string) error { return openBrowser(url) }
