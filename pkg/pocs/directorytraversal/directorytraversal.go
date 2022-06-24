package directorytraversal

import (
	"glint/logger"
	"glint/pkg/layers"
	"glint/util"
	"regexp"
	"strings"
)

type classInjectionPatterns struct {
	injectionValidator TInjectionValidator
}

type TInjectionValidator struct {
	StartMask string
	EndMask   string
}

type classDirectoryTraversal struct {
	scheme               string
	InjectionPatterns    classInjectionPatterns
	TargetUrl            string
	inputIndex           int
	reflectionPoint      int
	disableSensorBased   bool
	currentVariation     int
	foundVulnOnVariation bool
	variations           *util.Variations
	lastJob              layers.LastJob
	lastJobProof         interface{}
	injectionValidator   TInjectionValidator
}

var plainTexts = []string{
	"; for 16-bit app support",
	"[MCI Extensions.BAK]",
	"# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
	"# localhost name resolution is handled within DNS itself.",
	"[boot loader]",
}

var regexArray = []string{
	`(Linux+\sversion\s+[\d\.\w\-_\+]+\s+\([^)]+\)\s+\(gcc\sversion\s[\d\.\-_]+\s)`,
	`(Linux+\sversion\s+[\d\.\w\-_\+]+\s+&#x28;.*?&#x29;\s&#x28;gcc\sversion\s[\d\.]+\s&#x28;)`,
	`((root|bin|daemon|sys|sync|games|man|mail|news|www-data|uucp|backup|list|proxy|gnats|nobody|syslog|mysql|bind|ftp|sshd|postfix):[\d\w-\s,]+:\d+:\d+:[\w-_\s,]*:[\w-_\s,\/]*:[\w-_,\/]*[\r\n])`,
	`((root|bin|daemon|sys|sync|games|man|mail|news|www-data|uucp|backup|list|proxy|gnats|nobody|syslog|mysql|bind|ftp|sshd|postfix)\&\#x3a;[\d\w-\s,]+\&\#x3a;\d+\&\#x3a;[\w-_\s,]*\&\#x3a;[\d\w-\s,]+\&\#x3a;\&\#x2f;)`,
	`<b>Warning<\/b>:\s\sDOMDocument::load\(\)\s\[<a\shref='domdocument.load'>domdocument.load<\/a>\]:\s(Start tag expected|I\/O warning : failed to load external entity).*(Windows\/win.ini|\/etc\/passwd).*\sin\s<b>.*?<\/b>\son\sline\s<b>\d+<\/b>`,
	`(<web-app[\s\S]+<\/web-app>)`,
}

func (c *classInjectionPatterns) searchOnText(text string) (bool, string) {
	// _in := "body"
	// if strings.HasPrefix(text, "HTTP/1.") || strings.HasPrefix(text, "HTTP/0.") {
	// 	_in = "response"
	// }
	for _, v := range plainTexts {
		if strings.Index(text, v) != -1 {
			return true, v
		}
	}

	for _, v := range regexArray {
		r, _ := regexp.Compile(v)
		C := r.FindStringSubmatch(text)
		if len(C) > 0 {
			return true, C[0]
		}
	}

	return false, ""
}

//在响应中查找链接并验证他们
func (c *classDirectoryTraversal) verifyLinksForTraversal(varIndex int, value string, dontEncode bool) bool

//dontEncode 是否编码
func (c *classDirectoryTraversal) testInjection(varIndex int, value string, dontEncode bool) bool {
	var job = c.lastJob
	b, matchedText := c.InjectionPatterns.searchOnText(job.Features.Response.String())
	if b {
		// here we need to make sure it's not a false positive
		// mix up the value to cause the injection to fail, the patterns should not be present in response
		Feature, err := c.lastJob.RequestByIndex(varIndex, c.TargetUrl, util.RandStr(5))
		if err != nil {
			logger.Error("%s", err.Error())
			return false
		}
		var confirmed, _ = c.InjectionPatterns.searchOnText(Feature.Response.String())
		if confirmed {
			return true
		}
		// if isUnix || isUnknown {
		// 	if value == `/etc/passwd` {
		// 		if c.verifyLinksForTraversal(job, `passwd`, value) {
		// 			return false
		// 		}
		// 	}
		// }
	}
	return false
}
