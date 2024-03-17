package trivy

import "os/exec"

func ScanImage(image string) (string, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", "--scanners", "vuln", image)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		return string(stdout), err
	}
	return string(stdout), nil
}

type VulnerabilityReport struct {
	Results []struct {
		Vulnerabilities []interface{} `json:"Vulnerabilities"`
	} `json:"Results"`
}
