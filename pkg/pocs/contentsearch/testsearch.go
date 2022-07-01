package testsearch

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

func (s *classcontentsearch) CheckForEmailAddr(responseBody string, contentType string) (string, bool) {
	var excludedContentTypes = []string{
		"text/css", "application/javascript", "application/ecmascript", "application/x-ecmascript",
		"application/x-javascript", "text/javascript", "text/ecmascript", "text/javascript1.0",
		"text/javascript1.1", "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
		"text/javascript1.5", "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
	}
	if funk.Contains(excludedContentTypes, contentType) {
		return "", false
	}
	regexEmails := `(?i)([_a-z\d\-\.]+@([_a-z\d\-]+(\.[a-z]+)+))`
	re, _ := regexp.Compile(regexEmails)
	email_str := re.FindString(responseBody)
	if VaildEmail(email_str) && email_str != "" {
		return email_str, true
	}
	return "", false
}

func invalidIPAddress(input string) bool {
	regexIp := `\b(\.0\.0$`
	RE, _ := regexp.Compile(regexIp)
	if RE.Match([]byte(input)) {
		return true
	}
	return false
}
func (s *classcontentsearch) CheckForIpAddr(responseBody string) (string, bool) {
	regexIp := `\b(192\.168\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|172\.(?:16|17|18|19|(?:2[0-9])|30|31)\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|10\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5])))\b`
	RE, _ := regexp.Compile(regexIp)
	ips := RE.FindAllString(responseBody, -1)
	if len(ips) != 0 && !invalidIPAddress(ips[0]) {
		if !funk.Contains(s.TargetUrl, ips[0]) {
			return ips[0], true
		}
	}
	return "", false
}

func (s *classcontentsearch) CheckForTrojanShellScript(responseBody string) (string, bool) {
	regexes := []string{
		`(<title>nsTView\s\v[\s\S]*?nst.void.ru<\/title>[\s\S]*?<b>nsTView\sv[\s\S]*?<a\shref=http:\/\/nst.void.ru\sstyle\='text-decoration:none;'>[\s\S]*?<b>Host:<\/b>[\s\S]*?<b>IP:<\/b>[\s\S]*?<b>Your\sip:<\/b>)`,
		`(<\/font><\/b><\/td><td\sclass=td1\salign=left><input\stype=checkbox\sname=m\sid=m\svalue="1"><input\stype=text\sname=s_mask\ssize=82\svalue=".txt;.php">\*\s\(\s.txt;.php;.htm\s\)<input\stype=hidden\sname=cmd\svalue="search_text"><input\stype=hidden\sname=dir\svalue="[^"]*"><\/td><\/tr><\/table><\/)`,
		`(<\/th><\/tr><tr><td><p\salign="left"><b>Software:&nbsp;[\s\S]*act=phpinfo"\starget="[\s\S]*<\/b>&nbsp;<\/p><p\salign="left"><b>Safe-mode:&nbsp;<font\scolor=[\s\S]*act=ftpquickbrute&d=C%3A%[\s\S]*act=selfremove"><)`,
		`(<title>\sCrystal\sshell<\/title>[\s\S]*?<font size="1"\sface="Arial">Crystal hack shellphp<\/font><\/span>[\s\S]*2006-2007<\/span>)`,
		`(<pre><form\saction\=""\sMETHOD\=GET\s>execute\scommand\:\s<input\stype="text"\sname="c"><input\stype="submit"\svalue="go"><hr><\/form>)`,
		`(Usage\:\shttp\:\/\/target\.com\/simple-backdoor.php\?cmd=cat\+\/etc\/passwd)`,
		`(<FORM\saction="[\s\S]*?"\smethod="POST">\n<input\stype=text\sname="\.CMD"\ssize=45\svalue="">\n<input\stype=submit\svalue="Run">\n<\/FORM>)`,
		`(<title>[\s\S]*?WSO\s\d\.\d<\/title>[\s\S]*?<span>Execute:<\/span><br><input class='toolsInp' type=text name=c value=)`,
		`(<head><title>\n\s+ASPXSpy\d\.\d\s->\sBin\:\)\n<\/title>[\s\S]*<span\sid="PassLabel">Password:<\/span>)`,
		`(<h1>ASPX Shell by LT<\/h1>)`,
		`<b>Mass deface<\/b><\/u><\/a>.*<b>Bind<\/b><\/u><\/a>.*<b>Processes<\/b>.*<b>FTP Quick brute<\/b>.*<b>LSA<\/b>.*<b>SQL<\/b>.*<b>PHP-code<\/b>.*<b>PHP-info<\/b>.*<b>Self remove<\/b>.*<b>Logout<\/b>`,
		`<b>Encoder<\/b>.*<b>Bind<\/b>.*<b>Proc.<\/b>.*<b>FTP brute<\/b>.*<b>Sec.<\/b>.*<b>SQL<\/b>.*<b>PHP-code<\/b>.*<b>Feedback<\/b>.*<b>Self remove<\/b>.*<b>Logout<\/b>`,
		`\$sess_cookie = "c99shvars"; \/\/ cookie-variable name`,
		`<input type=text name="\.CMD" size=45 value="[^"<]*">[\n\r]{2}<input type=submit value="Run">`,
		`<input type=text name="\.CMD" size=45 value="<%= szCMD %>">[\n\r]{2}<input type=submit value="Run">`,
		`<title>nsTView v[^<]*<\/title>[\S\s]+<input type=password name=pass size=30 tabindex=1>\r\n<\/form>\r\n<b>Host:<\/b> [^<]*<br>\r\n<b>IP:<\/b>[^<]*<br>\r\n<b>Your ip:<\/b>[^<]*`,
		`<b>Rename<\/b><\/a><br><a href='\$php_self\?d=\$d&download=\$files\[\$i\]' title='Download \$files\[\$i\]'><b>Download<\/b><\/a><br><a href='\$php_self\?d=\$d&ccopy_to=\$files\[\$i]' title='Copy \$files\[\$i\] to\?'><b>Copy<\/b><\/a><\/div><\/td><td bgcolor=\$color>\$siz<\/td><td bgcolor=\$color><center>\$owner\/\$group<\/td><td bgcolor=\$color>\$info<\/td><\/tr>";`,
		`<b>Rename<\/b><\/a><br><a href='[^'$]*' title='[^'$]*'><b>Download<\/b><\/a><br><a href='[^'$]*' title='[^'$]*'><b>Copy<\/b><\/a><\/div><\/td><td bgcolor=[^>$]*>[^>$]*<\/td><td bgcolor=[^>$]*><center>[^>$]*<\/td><td bgcolor=[^>$]*>[^>$]*<\/td>`,
		`<pre><form action="[^<]*" METHOD=GET >execute command: <input type="text" name="c"><input type="submit" value="go">`,
		`<pre><form action="<\? echo \$PHP_SELF; \?>" METHOD=GET >execute command: <input type="text" name="c"><input type="submit" value="go">`,
		`<font color=black>\[<\/font> <a href=[^?]*\?phpinfo title="Show phpinfo\(\)"><b>phpinfo<\/b><\/a> <font color=black>\]<\/font>`,
		`<a href=".\$_SERVER\['PHP_SELF'\]."\?phpinfo title=\\"".\$lang\[\$language.'_text46'\]\."\\"><b>phpinfo<\/b><\/a>`,
		`<form name="myform" action="[^<"]*" method="post">\r\n<p>Current working directory: <b>\r\n<a href="[^"]*">Root<\/a>\/<\/b><\/p>`,
		`echo "<option value=\\"". strrev\(substr\(strstr\(strrev\(\$work_dir\), "\/"\), 1\)\) ."\\">Parent Directory<\/option>\\n";`,
		`<center><h2>vBulletin pwn v0\.1<\/h2><\/center><br \/><br \/><center>`,
		`<p class='danger'>Using full paths in your commands is suggested.<\/p>`,
		`<head><title>Win MOF Shell<\/title><\/head>`,
		`<title>Weakerthan PHP Exec Shell - 2015 WeakNet Labs<\/title>`,
	}
	for _, r := range regexes {
		RE, _ := regexp.Compile(r)
		matcharray := RE.FindAllString(responseBody, -1)
		if len(matcharray) != 0 {
			return matcharray[0], true
		}
	}
	return "", false
}

func (s *classcontentsearch) CheckForColdFusionPathDisclosure(responseBody string) (string, bool) {
	r1 := regexp.MustCompile(`The Error Occurred in <b>([\s\S]*): line[\s\S]*<\/b><br>`)
	r2 := regexp.MustCompile(`The error occurred while processing[\s\S]*Template: ([\s\S]*) <br>.`)
	r3 := regexp.MustCompile(`The error occurred while processing[\s\S]*in the template file ([\s\S]*)\.<\/p><br>`)
	var m []string
	m = r1.FindAllString(responseBody, -1)
	if len(m) == 0 {
		m = r2.FindAllString(responseBody, -1)
		if len(m) == 0 {
			m = r3.FindAllString(responseBody, -1)
		}
	}
	if len(m) != 0 {
		return m[0], true
	}
	return "", false
}

func (s *classcontentsearch) CheckForRSAPrivateKey(responseBody string) (string, bool) {
	r1 := regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----([\r\n][^\-]+)+-----END RSA PRIVATE KEY-----`)
	m := r1.FindAllString(responseBody, -1)
	if len(m) != 0 {
		return m[0], true
	}
	return "", false
}

func (s *classcontentsearch) CheckForASPNETPathDisclosure(responseBody string) (string, bool) {
	r1 := regexp.MustCompile(`<title>Invalid\sfile\sname\sfor\smonitoring:\s'([^']*)'\.\sFile\snames\sfor\smonitoring\smust\shave\sabsolute\spaths\,\sand\sno\swildcards\.<\/title>`)
	m := r1.FindAllString(responseBody, -1)
	if len(m) != 0 {
		return m[0], true
	}
	return "", false
}

func (s *classcontentsearch) CheckForMySQLConnectionInfo(responseBody string) (string, bool) {
	if !funk.Contains(responseBody, `<?`) {
		return "", false
	}

	r1 := regexp.MustCompile(`mysql_[p]*connect\(["']{0,1}[a-z0-9\-\.]+["']{0,1}\s*,`)
	m := r1.FindAllString(responseBody, -1)
	if len(m) != 0 {
		return m[0], true
	}

	return "", false
}

func (s *classcontentsearch) CheckForDatabaseConnectionStringDisclosure(responseBody string) (string, bool) {
	if !funk.Contains(responseBody, `;DATABASE=`) && !funk.Contains(responseBody, `;UID=`) && !funk.Contains(responseBody, `;PWD=`) {
		return "", false
	}

	if !funk.Contains(responseBody, `!function(`) || !funk.Contains(responseBody, `function(`) || !funk.Contains(responseBody, `(window.webpackJsonp=`) {
		return "", false
	}
	m := []string{}
	r1 := regexp.MustCompile(`.*?(;DATABASE=[a-zA-Z0-9]+;UID=[a-zA-Z0-9]+;.*?;PWD=).*`)
	m = r1.FindAllString(responseBody, -1)
	if len(m) == 0 {
		r2 := regexp.MustCompile(`.*?(;DATABASE=[a-zA-Z0-9]+;UID=[a-zA-Z0-9]+;.*?;PWD=).*`)
		m = r2.FindAllString(responseBody, -1)
	}
	if len(m) != 0 {
		return m[0], true
	}
	return "", false
}
func (s *classcontentsearch) CheckForUsernameOrPasswordDisclosure(responseBody string) (string, bool) {
	r1 := regexp.MustCompile(`(?i)(?m)(['"]?(db[\-_])?(uid|user|username)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){3,}['"]?[,]?([\r\n]+)\s*['"]?(db[\-_])?(pass|pwd|passwd|password)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){6,}['"]?([,\r\n]|$))`)
	m := r1.FindAllString(responseBody, -1)
	if len(m) != 0 {
		return m[0], true
	}
	return "", false
}

func (s *classcontentsearch) CheckForPathDisclosure(responseBody string, fullPath string) (string, bool) {
	// Windows
	r1 := regexp.MustCompile(`(?i)([a-z])\:\\(program files|windows|inetpub|php|document and settings|www|winnt|xampp|wamp|temp|websites|apache|apache2|site|sites|htdocs|web|http|appserv)[\\\w]+(\.\w+)?`)
	m := r1.FindAllString(responseBody, -1)
	if len(m) != 0 {
		return m[0], true
	}
	// Unix
	r2 := regexp.MustCompile(`[\s\t:><|\(\)\[\}](\/(var|www|usr|Users|user|tmp|etc|home|mnt|mount|root|proc)\/[\w\/\.]*(\.\w+)?)`)
	m2 := r2.FindAllString(responseBody, -1)
	if len(m2) != 0 {
		if strings.HasSuffix(m2[0], fullPath) {
			return "", false
		}
		fileExts := strings.Split(m2[0], ".")
		if len(fileExts) != 0 {
			fExt := fileExts[len(fileExts)-1]
			if fExt == "js" {
				return "", false
			}
		}

		DIRS := strings.Split(m2[0], "/")
		if len(DIRS) < 3 {
			return "", false
		}

		return m[0], true
	}
	return "", false
}

func (s *classcontentsearch) CheckForDjangoDebugMode(responseBody string) (string, bool) {
	r1 := regexp.MustCompile(`(?i)(?m)<th>Django Version:<\/th>[\S\s]*<th>Exception Type:<\/th>`)
	m := r1.FindAllString(responseBody, -1)
	if len(m) != 0 {
		return m[0], true
	}
	return "", false
}
