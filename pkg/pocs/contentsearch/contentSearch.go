package contentsearch

import (
	"glint/pkg/layers"
	"glint/util"
	"regexp"
	"strings"

	"github.com/thoas/go-funk"
)

type classcontentsearch struct {
	scheme layers.Scheme
	// InjectionPatterns      classInjectionPatterns
	TargetUrl            string
	inputIndex           int
	reflectionPoint      int
	disableSensorBased   bool
	currentVariation     int
	foundVulnOnVariation bool
	variations           *util.Variations
	lastJob              layers.LastJob
	lastJobProof         interface{}
	// injectionValidator     TInjectionValidator
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
}

func VaildEmail(email string) bool {
	var skippedEndings = []string{
		"@example.com",
		".example.com",
		"@sample.com",
		"@email.tst",
		"@domain.com",
		"@sitename.com",
		"@php.net",
		"@httpd.apache.org",
		"@magento.com",
		"@email.com",
		".png",
		".jpeg",
		".gif",
		".jpg",
		".bmp",
		".tif",
		".svg",
	}
	var skippedEmails = []string{
		"webmaster@", "hostmaster@", "info@", "support@", "sales@", "marketing@", "news@", "contact@", "helpdesk@", "help@", "sample@", "postmaster@", "security@", "root@",
		"sysadmin@", "abuse@",
		"admin@", "administrator@",
		"noreply@", "no-reply@",
		"your@", "your@friend.com",
	}
	if email != "" {
		regstr := "(?i)(^u00[a-f0-9]{2})"
		re, _ := regexp.Compile(regstr)
		if re.Match([]byte(email)) {
			return false
		}
		for _, v := range skippedEndings {
			if strings.HasSuffix(strings.ToLower(email), v) {
				return false
			}
		}
		for _, v := range skippedEmails {
			if strings.HasPrefix(strings.ToLower(email), v) {
				return false
			}
		}
	}
	return true
}

func (s *classcontentsearch) CheckForEmailAddr(responseBody string, contentType string) bool {
	var excludedContentTypes = []string{
		"text/css", "application/javascript", "application/ecmascript", "application/x-ecmascript",
		"application/x-javascript", "text/javascript", "text/ecmascript", "text/javascript1.0",
		"text/javascript1.1", "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
		"text/javascript1.5", "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
	}
	if funk.Contains(excludedContentTypes, contentType) {
		return false
	}
	var regexEmails = `(?i)([_a-z\d\-\.]+@([_a-z\d\-]+(\.[a-z]+)+))`

	return false
}
