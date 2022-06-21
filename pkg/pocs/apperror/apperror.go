package apperror

import (
	"bytes"
	"encoding/json"
	"fmt"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	"glint/util"
	"regexp"
	"strings"
	"time"

	"github.com/thoas/go-funk"
)

var plainArray = []string{
	`Microsoft OLE DB Provider for ODBC Drivers`,
	`java.io.FileNotFoundException:`,
	`Microsoft OLE DB Provider for SQL Server`,
	`<h1 class="t-exception-report">An unexpected application exception has occurred.</h1>`,
	`Incorrect syntax near `,
	`undefined alias:`,
	`<abbr title="ErrorException">ErrorException</abbr>`,
	`<h1>Grails Runtime Exception</h1>`,
	`<pre><code>com.sun.facelets.FaceletException`,
	`<title>Error - org.apache.myfaces`,
	`com.google.gwt.http.client.RequestException`,
	`<title>Grails Runtime Exception</title>`,
	`onclick="toggle(\'full exception chain stacktrace`,
	`at org.apache.catalina`,
	`at org.apache.coyote.`,
	`at org.jboss.seam.`,
	`at org.apache.tomcat.`,
	`Struts has detected an unhandled exception:`,
	`DatabaseError:`,
	`SyntaxError: Unexpected token `,
	`SyntaxError: Unexpected identifier`,
	`SyntaxError: Unexpected number`,
	`SyntaxError: Unexpected end of input`,
	`SQLite3::SQLException:`,
	`System.Data.SqlClient.SqlException:`,
	`ODBC Microsoft Access Driver`,
	`ODBC SQL Server Driver`,
	`supplied argument is not a valid MySQL result`,
	`You have an error in your SQL syntax`,
	`Incorrect column name`,
	`Can\'t find record in`,
	`Unknown table`,
	`Incorrect column specifier for column`,
	`Column count doesn\'t match value count at row`,
	`Unclosed quotation mark before the character string`,
	`Unclosed quotation mark`,
	`Invalid SQL:`,
	`ERROR: parser: parse error at or near`,
	`java.lang.NumberFormatException: For input string:`,
	`): encountered SQLException [`,
	`Unexpected end of command in statement [`,
	`[ODBC Informix driver][Informix]`,
	`[Microsoft][ODBC Microsoft Access 97 Driver]`,
	`[SQL Server Driver][SQL Server]Line 1: Incorrect syntax near`,
	`SQL command not properly ended`,
	`unexpected end of SQL command`,
	`Supplied argument is not a valid PostgreSQL result`,
	`internal error [IBM][CLI Driver][DB2/6000]`,
	`Query failed: ERROR: unterminated quoted string at or near`,
	`pg_fetch_row() expects parameter 1 to be resource, boolean given in`,
	`<pre>Internal Server Error</pre>`,
	`<title>Error: 500 Internal Server Error</title>`,
	`<pre>Traceback (most recent call last):`,
	`Traceback (most recent call last):`,
	`Error Occurred While Processing Request`,
	`A syntax error has occurred`,
	`ADODB.Field error`,
	`ASP.NET is configured to show verbose error messages`,
	`Active Server Pages error`,
	`An illegal character has been found in the statement`,
	`An unexpected token "END-OF-STATEMENT" was found`,
	`Disallowed Parent Path`,
	`Error Diagnostic Information`,
	`Error Message : Error loading required libraries`,
	`Error converting data type varchar to numeric`,
	`Microsoft SQL Native Client error`,
	`Microsoft VBScript runtime error`,
	`Fatal error`,
	`Invalid multibyte sequence in argument`,
	`Incorrect syntax near`,
	`Invalid Path Character`,
	`Invalid procedure call or argument`,
	`SqlException`,
	`JDBC Driver`,
	`JDBC Error`,
	`JDBC MySQL`,
	`JDBC Oracle`,
	`JDBC SQL`,
	`MySQL Driver`,
	`MySQL Error`,
	`MySQL ODBC`,
	`ODBC DB2`,
	`ODBC Driver`,
	`ODBC Error`,
	`ODBC Microsoft Access`,
	`ODBC Oracle`,
	`ODBC SQL`,
	`ODBC SQL Server`,
	`OLE/DB provider returned message`,
	`Oracle DB2`,
	`Oracle Driver`,
	`Oracle Error`,
	`Oracle ODBC`,
	`Syntax error in query expression`,
	`The error occurred in`,
	`Warning: Cannot modify header information - headers already sent`,
	`Warning: pg_connect(): Unable to connect to PostgreSQL server:`,
	`missing expression`,
	`server object error`,
	`supplied argument is not a valid MySQL result resource`,
	`PostgreSQL query failed`,
	`Must declare the scalar variable`,
	`Invalid column name`,
	`unterminated quoted string at or near`,
	`Error Occurred While Processing Request`,
	`System.Data.SqlClient.SqlException`,
	`MS.Internal.Xml.`,
	`Unknown error in XPath`,
	`org.apache.xpath.XPath`,
	`A closing bracket expected in`,
	`An operand in Union Expression does not produce a node-set`,
	`Cannot convert expression to a number`,
	`Document Axis does not allow any context Location Steps`,
	`Empty Path Expression`,
	`Empty Relative Location Path`,
	`Empty Union Expression`,
	`Expected node test or name specification after axis operator`,
	`Incompatible XPath key`,
	`Incorrect Variable Binding`,
	`error \'80004005\'`,
	`libxml2 library function failed`,
	`A document must contain exactly one root element.`,
	`<font face="Arial" size=2>Expression must evaluate to a node-set.`,
	`Expected token \']\'`,
	`javax.crypto.BadPaddingException: Given final block not properly padded`,
	`Given final block not properly padded`,
	`javax.crypto.BadPaddingException`,
	`Padding is invalid and cannot be removed.`,
	`padding byte out of range`,
	`supplied argument is not a valid ldap`,
	`javax.naming.NameNotFoundException`,
	`LDAPException`,
	`com.sun.jndi.ldap`,
	`Protocol error occurred`,
	`Size limit has exceeded`,
	`An inappropriate matching occurred`,
	`A constraint violation occurred`,
	`The syntax is invalid`,
	`Object does not exist`,
	`The distinguished name has an invalid syntax`,
	`The server does not handle directory requests`,
	`The alias is invalid`,
	`There was a naming violation`,
	`There was an object class violation`,
	`Results returned are too large`,
	`The search filter is incorrect`,
	`The search filter is invalid`,
	`The search filter cannot be recognized`,
	`Invalid DN syntax`,
	`unterminated quoted identifier at or near`,
	`syntax error at end of input`,
	`MongoCursorException`,
	`No Such Object`,
	`<title>Struts Problem Report</title>`,
	`<h1>An Error Occurred:</h1>`,
	`<title>Action Controller: Exception caught</title>`,
	`SQLite3::query(): Unable to prepare statement:`,
	`javax.servlet.ServletException`,
	`<b>SQL error: </b> no such column`,
	`<b> Source File: </b>`,
	`<b>Stack Trace:</b>`,
	`org.hibernate.exception.SQLGrammarException:`,
	`org.hibernate.QueryException`,
	`servlet.exception`,
	`<dt>Environment variables</dt>`,
	` - Generated by Mojarra/Facelets`,
	`You're seeing this error because you have `,
	`PDOStatement::execute():`,
	`You are seeing this page because development mode is enabled.  Development mode, or devMode, enables extra`,
}

var regexArray = []string{
	`(Incorrect\ssyntax\snear\s'[^']*')`,
	`<th\salign='left'\sbgcolor='#[a-zA-Z0-9]+'\scolspan="[a-zA-Z0-9]+"><span\sstyle='background-color:\s#[a-zA-Z0-9]+;\scolor:\s#[a-zA-Z0-9]+;\sfont-size:\sx-large;'>\(\s\!\s\)<\/span>\s+(.*?on\s+line\s<i>\d+<\/i>)<\/th>`,
	`(pg_query\(\)[:]*\squery\sfailed:\serror:\s)`,
	`('[^']*'\sis\snull\sor\snot\san\sobject)`,
	`(Syntax error: Missing operand after '[^']*' operator)`,
	`(ORA-\d{4,5}:\s)`,
	`(Microsoft\sJET\sDatabase\sEngine\s\([^\)]*\)<br>Syntax\serror(.*)\sin\squery\sexpression\s'.*\.<br><b>.*,\sline\s\d+<\/b><br>)`,
	`(<h2>\s<i>Syntax\serror\s(\([^\)]*\))?(in\sstring)?\sin\squery\sexpression\s'[^\.]*\.<\/i>\s<\/h2><\/span>)`,
	`(<font\sface=\"Arial\"\ssize=2>Syntax\serror\s(.*)?in\squery\sexpression\s'(.*)\.<\/font>)`,
	`(<b>Warning<\/b>:\s\spg_exec\(\)\s\[\<a\shref='function.pg\-exec\'\>function\.pg-exec\<\/a>\]\:\sQuery failed:\sERROR:\s\ssyntax error at or near \&quot\;\\\&quot; at character \d+ in\s<b>.*<\/b>)`,
	`(System\.Data\.OleDb\..*)`,
	`(System\.InvalidOperationException.*)`,
	`(Data type mismatch in criteria expression|Could not update; currently locked by user '.*?' on machine '.*?')`,
	`(<font style="COLOR: black; FONT: 8pt\/11pt verdana">\s+(\[Macromedia\]\[SQLServer\sJDBC\sDriver\]\[SQLServer\]|Syntax\serror\sin\sstring\sin\squery\sexpression\s))`,
	`(Unclosed\squotation\smark\safter\sthe\scharacter\sstring\s'[^']*')`,
	`(<b>Warning<\/b>:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\): supplied argument is not a valid MySQL result resource in <b>.*?<\/b> on line <b>.*?<\/b>)`,
	`(You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '[^']*' at line \d)`,
	`(Query\sfailed\:\sERROR\:\scolumn\s"[^"]*"\sdoes\snot\sexist\sLINE\s\d)`,
	`(Query\sfailed\:\sERROR\:\s+unterminated quoted string at or near)`,
	`The Error Occurred in <b>(.*): line.*<\/b><br>`,
	`The error occurred while processing.*Template: (.*) <br>.`,
	`The error occurred while processing.*in the template file (.*)\.<\/p><br>`,
	`<title>Invalid\sfile\sname\sfor\smonitoring:\s'([^']*)'\.\sFile\snames\sfor\smonitoring\smust\shave\sabsolute\spaths\,\sand\sno\swildcards\.<\/title>`,
	`(<b>(Warning|Fatal\serror|Parse\serror)<\/b>:\s+.*?\sin\s<b>.*?<\/b>\son\sline\s<b>\d*?<\/b><br\s\/>)`,
	`(<\/span>\s(Warning|Fatal\serror|Parse\serror):\s+.*?\sin\s.*?\son\sline\s<i>\d*?<\/i>)`,
	`((?:Unknown database '.*?')|(?:No database selected)|(?:Table '.*?' doesn't exist)|(?:You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '.*?' at line .*?))`,
	`(Exception report.*message.*description.*exception.*note.*)`,
	`(<head><title>JRun Servlet Error<\/title><\/head>)`,
	`(<h1>Servlet\sError:\s\w+?<\/h1>)`,
	`(Servlet\sError<\/title>)`,
	`(<b>\sException\sDetails:\s<\/b>System\.Xml\.XPath\.XPathException:\s'.*'\shas\san\sinvalid\stoken\.<br><br>)`,
	`(<b>\sException\sDetails:\s<\/b>System\.Xml\.XPath\.XPathException:\sThis\sis\san\sunclosed\sstring\.<br><br>)`,
	`(System.Xml.XPath.XPathException\:)`,
	`(<b>Fatal error<\/b>:.*: Failed opening required '.*').*`,
	`(<b>Warning<\/b>:.*: Failed opening '.*') for inclusion.*`,
	`(org.apache.jasper.JasperException: .*? File .*? not found)`,
	`(Failed opening '.*' for inclusion)`,
	`(Unknown column '[^']+' in '\w+ clause')`,
	`(IPWorksASP\.LDAP.*800a4f70.*\[335\]\s\(no description\savailable\))`,
	`(<span><H1>Server Error in '.*?' Application.*<h2>\s<i>The.*search filter is invalid\.<\/i>)`,
	`\d{4}\s\d{2}:\d{2}:\d{2} - Generated by MyFaces - for information on disabling or modifying this error-page, see`,
	`(\s+(at)?\s(org|net|java|com|javax|ruby|sun|hudson|winstone|jpp)\.[\w\.\$]+\(.*?:\d+\)){5,}`,
	`(<title>.*?Exception caught<\/title>)`,
	`(Traceback \(most recent call last\):\s+File\s")`,
	`(Microsoft\sJET\sDatabase\sEngine\s\([^\)]*\)<br>Syntax\serror([\s\S]*)\sin\squery\sexpression\s'[\s\S]*\.<br><b>[\s\S]*,\sline\s\d+<\/b><br>)`,
	`(<font\sface=\"Arial\"\ssize=2>Syntax\serror\s([\s\S]*)?in\squery\sexpression\s'([\s\S]*)\.<\/font>)`,
	`(<b>Warning<\/b>:\s\spg_exec\(\)\s\[\<a\shref='function.pg\-exec\'\>function\.pg-exec\<\/a>\]\:\sQuery failed:\sERROR:\s\ssyntax error at or near \&quot\;\\\&quot; at character \d+ in\s<b>[\s\S]*<\/b>)`,
	`(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\s\([^)]*?\)\sin\squery\sexpression\s[\s\S]*)`,
	`(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\sin\sstring\sin\squery\sexpression\s)`,
	`(Data type mismatch in criteria expression|Could not update; currently locked by user '[\s\S]*?' on machine '[\s\S]*?')`,
	`(<b>Warning<\/b>:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\): supplied argument is not a valid MySQL result resource in <b>[\s\S]*?<\/b> on line <b>[\s\S]*?<\/b>)`,
	`The Error Occurred in <b>([\s\S]*): line[\s\S]*<\/b><br>`,
	`The error occurred while processing[\s\S]*Template: ([\s\S]*) <br>.`,
	`The error occurred while processing[\s\S]*in the template file ([\s\S]*)\.<\/p><br>`,
	`(<b>(Warning|Fatal\serror|Parse\serror)<\/b>:\s+[\s\S]*?\sin\s<b>[\s\S]*?<\/b>\son\sline\s<b>\d*?<\/b><br\s\/>)`,
	`((?:Unknown database '[\s\S]*?')|(?:No database selected)|(?:Table '[\s\S]*?' doesn't exist)|(?:You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '[\s\S]*?' at line [\s\S]*?))`,
	`(Exception report[\s\S]*message[\s\S]*description[\s\S]*exception[\s\S]*note[\s\S]*)`,
	`((Warning|Fatal\serror|Parse\serror):\s+[\s\S]*\([^\)]*\)\:\s[\s\S]*?\sin\s[\s\S]*?\son\sline\s\d+)`,
	`(\[IBM\]\[CLI Driver\]\[DB2\/.*?\])`,
	`(?i)(SQL[\s\S]error[\s\S]*)`,
	`(\s+at\s\w+\.[\s\S]*?\(\w+\.java\:\d+\)\n){3,}`,
	`Microsoft VBScript (?:runtime|compilation)\s<\/font>\s<font.*?>error\s'[a-f0-9]+'<\/font>`,
}

//这个就在主要插件中调用回调会好点。
func Test_Application_error(body string) (bool, string) {
	//var MatchString string
	for _, plain := range plainArray {
		if funk.Contains(body, plain) {
			return true, plain
		}
	}
	for _, regex := range regexArray {
		r, _ := regexp.Compile(regex)
		C := r.FindAllStringSubmatch(body, -1)
		if len(C) != 0 {
			return true, C[0][0]
		}
	}
	return false, ""
}

var DefaultProxy = ""
var cert string
var mkey string

type ErrorVulnDetail struct {
	Url         string `json:"url"`
	MatchString string `json:"matchString"`
}

type ErrorVulnDetails struct {
	VulnerableList []ErrorVulnDetail
}

func (e *ErrorVulnDetails) String() string {
	var buf bytes.Buffer
	for _, v := range e.VulnerableList {
		buf.WriteString(fmt.Sprintf("Url:%s\n", v.Url))
		buf.WriteString(fmt.Sprintf("%s\n", v.MatchString))
	}
	return buf.String()
}

func Application_startTest(args interface{}) (*util.ScanResult, bool, error) {
	util.Setup()
	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}
	IsVuln := false
	var hostid int64
	var VulnURl = ""
	var VulnList = ErrorVulnDetails{}
	var err error
	if sessions, ok := group.GroupUrls.([]interface{}); ok {
		for _, session := range sessions {
			newsess := session.(map[string]interface{})

			url := newsess["url"].(string)
			method := newsess["method"].(string)
			headers, _ := util.ConvertHeaders(newsess["headers"].(map[string]interface{}))
			body := []byte(newsess["data"].(string))
			cert = group.HttpsCert
			mkey = group.HttpsCertKey
			sess := fastreq.GetSessionByOptions(
				&fastreq.ReqOptions{
					Timeout:       2 * time.Second,
					AllowRedirect: true,
					Proxy:         DefaultProxy,
					Cert:          cert,
					PrivateKey:    mkey,
				})

			if hostid == 0 {
				if value, ok := newsess["hostid"].(int64); ok {
					hostid = value
				}
				if value, ok := newsess["hostid"].(json.Number); ok {
					hostid, _ = value.Int64()
				}
			}
			_, resp, err := sess.Request(strings.ToUpper(method), url, headers, body)
			if err != nil {
				logger.Error("%s", err.Error())
			}
			if isVuln, matchstr := Test_Application_error(resp.String()); isVuln {
				IsVuln = true
				if VulnURl == "" {
					VulnURl = url
				}
				VulnInfo := ErrorVulnDetail{Url: url, MatchString: matchstr}
				VulnList.VulnerableList = append(VulnList.VulnerableList, VulnInfo)
			}
		}

	}
	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(VulnURl,
			VulnList.String(),
			[]string{""},
			[]string{""},
			"middle",
			hostid)
		return Result, true, err
	}
	return nil, false, err
}
