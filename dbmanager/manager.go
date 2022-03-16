package dbmanager

import (
	"database/sql"
	"fmt"
	"glint/config"
	"glint/logger"
	"reflect"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type DbManager struct {
	Db *sqlx.DB
}

type DbTargetInfo struct {
	Urls sql.NullString `db:"scan_target"`
}

type DbHostResult struct {
	Hostid     sql.NullInt64  `db:"host_id"`
	Taskid     sql.NullInt64  `db:"task_id"`
	ScanTarget sql.NullString `db:"scan_target"`
	Hostip     sql.NullString `db:"host_ip"`
	StartTime  sql.NullTime   `db:"start_time"`
	EndTime    sql.NullTime   `db:"end_time"`
	ServerType sql.NullString `db:"server_type"`
	ServerOs   sql.NullString `db:"server_os"`
	RiskLevel  sql.NullString `db:"risk_level"`
	Headeruuid sql.NullString `db:"header_uuid"`
}

type DbTaskConfig struct {
	Configid sql.NullInt64 `db:"web_param_id"`
	TaskId   sql.NullInt64 `db:"task_id"`
	// Urls                        sql.NullString
	ParamModelId                sql.NullInt64  `db:"param_model_id"`
	FilterMode                  sql.NullString `db:"filter_mode"`
	ExtraHeadersUuid            sql.NullString `db:"extra_headers_id"`
	AllDomainReturn             sql.NullBool   `db:"is_all_domain"`
	SubDomainReturn             sql.NullBool   `db:"is_sub_domain"`
	IncognitoContext            sql.NullBool   `db:"is_invisible_mode"`
	NoHeadless                  sql.NullBool   `db:"is_no_headless"`
	DomContentLoadedTimeout     sql.NullInt64  `db:"dom_timeout"`
	TabRunTimeout               sql.NullInt64  `db:"request_timeout"`
	PathByFuzz                  sql.NullBool   `db:"is_fuzz_dict"`
	FuzzDictPath                sql.NullString `db:"fuzz_dict_value"`
	PathFromRobots              sql.NullBool   `db:"robot_path"`
	MaxTabsCount                sql.NullInt64  `db:"max_page_count"`
	ChromiumPath                sql.NullString `db:"chrom_path"`
	EventTriggerMode            sql.NullString `db:"event_trigger_mode"`
	EventTriggerInterval        sql.NullInt64  `db:"event_trigger_interval"`
	BeforeExitDelay             sql.NullInt64  `db:"exit_delay_time"`
	EncodeURLWithCharset        sql.NullBool   `db:"is_auto_check_code"`
	IgnoreKeywords              sql.NullString `db:"ignore_events"`
	Proxy                       sql.NullString `db:"http_proxy"`
	CustomFormValuesUuid        sql.NullString `db:"custom_fill_form_id"`
	CustomFormKeywordValuesUuid sql.NullString `db:"custom_fill_keyword_id"`
	XssPayloadsUuid             sql.NullString `db:"xss_paloads_id"`
}

type ExtraHeaders struct {
	Key   string `db:"header_key"`
	Value string `db:"header_value"`
}

type PublishState struct {
	Id          sql.NullString `db:"msg_id"`
	Host        sql.NullString `db:"host_info"`
	Method      sql.NullString `db:"request_mode"`
	Data        sql.NullString `db:"post_param"`
	UserAgent   sql.NullString `db:"user_agent"`
	ContentType sql.NullString `db:"content_type"`
	CreatedTime time.Time      `db:"create_time"`
}

//Init 初始化mysql数据库
func (Dm *DbManager) Init() error {
	//构建连接："用户名:密码@tcp(IP:端口)/数据库?charset=utf8"
	path := strings.Join([]string{config.UserName,
		":", config.Password,
		"@tcp(", config.Ip,
		":", config.Port,
		")/", config.DbName,
		"?charset=utf8&parseTime=true&loc=Local"}, "")
	//打开数据库,前者是驱动名，所以要导入： _ "github.com/go-sql-driver/mysql"
	DB, err := sqlx.Connect("mysql", path)
	if err != nil {
		return err
	}
	DB.SetMaxOpenConns(20)
	DB.SetMaxIdleConns(10)
	DB.SetConnMaxLifetime(59 * time.Second)
	if err != nil {
		logger.Info("[DB] open database fail")
		return err
	}
	logger.Info("[DB] connnect success")
	Dm.Db = DB
	return nil
}

//GetTaskHostid
func (Dm *DbManager) GetTaskHostid(taskid int) ([]DbHostResult, error) {
	sql := `
	SELECT
	exweb_host_result.host_id,
	exweb_host_result.scan_target,
	exweb_host_result.start_time, 
	exweb_host_result.end_time,	
	exweb_host_result.server_type,
	exweb_host_result.server_os,
	exweb_host_result.risk_level,
	exweb_host_result.header_uuid
	FROM
	exweb_host_result
	WHERE
	exweb_host_result.task_id = ?`
	values := []DbHostResult{}

	err := Dm.Db.Select(&values, sql, taskid)
	if err != nil {
		logger.Error("get get task hostid error %v", err.Error())
	}
	return values, err
}

// Get

//GetTaskConfig 根据任务ID获取数据库的扫描配置
func (Dm *DbManager) GetTaskConfig(taskid int) (DbTaskConfig, error) {
	sql := `
	SELECT
		exweb_scan_param.*
	FROM
		exweb_scan_param
	WHERE
		exweb_scan_param.task_id = ?
	`
	values := DbTaskConfig{}
	err := Dm.Db.Get(&values, sql, taskid)
	if err != nil {
		logger.Error("get exweb_scan_param error %v", err.Error())
	}
	//两张表
	// sql = `
	// SELECT
	// exweb_target_info.scan_target
	// FROM
	// exweb_target_info
	// WHERE
	// exweb_target_info.task_id = ?
	// `
	// val2 := DbTargetInfo{}
	// err = Dm.Db.Get(&val2, sql, taskid)
	// if err != nil {
	// 	logger.Error("gettaskConfig error %v", err.Error())
	// }
	// values.Urls = val2.Urls
	return values, err
}

//GetExtraHeaders 根据Uuid获取数据库的扫描头
func (Dm *DbManager) GetExtraHeaders(uuid string) ([]ExtraHeaders, error) {
	sql := `
	SELECT
	exweb_header_info.header_key, 
	exweb_header_info.header_value
	FROM
	exweb_header_info
	WHERE
	exweb_header_info.header_uuid = ?`
	values := []ExtraHeaders{}
	err := Dm.Db.Select(&values, sql, uuid)
	if err != nil {
		logger.Error("get extra headers error %v", err.Error())
	}
	return values, err
}

//保存漏扫结果
func (Dm *DbManager) SaveScanResult(
	taskid int,
	plugin_name string,
	Vulnerable bool,
	Target string,
	ReqMsg string,
	RespMsg string,
	hostid int,
) error {
	sql := `
	INSERT  
	INTO 
	exweb_task_result (task_id,is_vul,url,vul_id,request_info,host_id) 
	VALUES(:taskid,:vul,:target,:vulid,:reqmsg,:hostid);
	`
	_, err := Dm.Db.NamedExec(sql, map[string]interface{}{
		"taskid": taskid,
		"vul":    Vulnerable,
		"target": Target,
		"vulid":  plugin_name,
		"reqmsg": ReqMsg,
		"hostid": hostid,
		// "respmsg": RespMsg,
		// "vulnerability": VulnerableLevel,
	})
	if err != nil {
		logger.Error("save scan result error %v", err.Error())
	}
	return err
}

//保存漏扫结果
func (Dm *DbManager) SaveQuitTime(
	taskid int,
	t time.Time,
	over string,
) error {
	sql := `UPDATE exweb_task_info SET end_time=:end_time,task_status=:task_status,scan_time=:scan_time WHERE task_id=:task_id`
	_, err := Dm.Db.NamedExec(sql,
		map[string]interface{}{
			"end_time":    t,
			"task_status": uint16(3),
			"task_id":     taskid,
			"scan_time":   over,
		})
	//错误处理
	if err != nil {
		fmt.Println("更新退出时间失败!")
	}
	return err
}

//DeleteScanResult 开始扫描时候删除脚本
func (Dm *DbManager) DeleteScanResult(taskid int) error {
	_, err := Dm.Db.Exec("delete from exweb_task_result where task_id=?", taskid)
	if err != nil {
		logger.Error("delete scan result error %v", err.Error())
	}
	return err
}

func (Dm *DbManager) ConvertToMap(value interface{}, converted map[string]interface{}) map[string]interface{} {
	// converted := make(map[string]interface{})
	rv := reflect.ValueOf(value)
	rt := reflect.TypeOf(value)
	if _, ok := rt.FieldByName("Key"); ok {
		if _, ok := rt.FieldByName("Value"); ok {
			converted[rv.FieldByName("Key").String()] = rv.FieldByName("Value").String()
		}
	}
	return converted
}

func (Dm *DbManager) UuidToMap(uuid string, type_name string) map[string]interface{} {
	converted := make(map[string]interface{})
	if uuid == "" {
		return converted
	}
	switch type_name {
	case "Headers":
		ExtraHeaders, err := Dm.GetKeyValues(uuid, 1)
		if err != nil {
			logger.Error(err.Error())
		}
		for _, Header := range ExtraHeaders {
			converted = Dm.ConvertToMap(Header, converted)
		}
	}
	return converted
}

func NewNullString(s string) sql.NullString {
	if len(s) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}

func (Dm *DbManager) InstallHttpsReqStatus(State *PublishState) error {

	sql := `
	INSERT
	INTO
	exweb_publish_msg (msg_id,host_info,request_mode,post_param,user_agent,content_type,create_time) 
	VALUES(:id,:host,:method,:data,:user_agent,:content_type,:created_time); 
	`
	_, err := Dm.Db.NamedExec(sql, map[string]interface{}{
		"id":           State.Id,
		"host":         State.Host,
		"method":       State.Method,
		"data":         State.Data,
		"user_agent":   State.UserAgent,
		"content_type": State.ContentType,
		"created_time": State.CreatedTime,
	})
	if err != nil {
		logger.Error("install https req status error %v", err.Error())
	}
	return err
}

func (Dm *DbManager) ConvertDbTaskConfigToJson(dbTaskConfig DbTaskConfig) (config.TaskConfig, error) {
	TaskConfig := config.TaskConfig{}
	TaskConfig.MaxTabsCount = int(dbTaskConfig.MaxTabsCount.Int64)
	TaskConfig.FilterMode = dbTaskConfig.FilterMode.String
	TaskConfig.ExtraHeaders = Dm.UuidToMap(dbTaskConfig.ExtraHeadersUuid.String, "Headers")
	TaskConfig.AllDomainReturn = dbTaskConfig.AllDomainReturn.Bool
	TaskConfig.SubDomainReturn = dbTaskConfig.SubDomainReturn.Bool
	TaskConfig.IncognitoContext = dbTaskConfig.IncognitoContext.Bool
	TaskConfig.NoHeadless = dbTaskConfig.NoHeadless.Bool
	TaskConfig.DomContentLoadedTimeout = time.Duration(dbTaskConfig.DomContentLoadedTimeout.Int64)
	TaskConfig.TabRunTimeout = time.Duration(dbTaskConfig.TabRunTimeout.Int64)
	TaskConfig.PathByFuzz = dbTaskConfig.PathByFuzz.Bool
	TaskConfig.FuzzDictPath = dbTaskConfig.FuzzDictPath.String
	TaskConfig.PathFromRobots = dbTaskConfig.PathFromRobots.Bool
	TaskConfig.ChromiumPath = dbTaskConfig.ChromiumPath.String
	TaskConfig.EventTriggerMode = dbTaskConfig.EventTriggerMode.String
	TaskConfig.EventTriggerInterval = time.Duration(dbTaskConfig.EventTriggerInterval.Int64)
	TaskConfig.BeforeExitDelay = time.Duration(dbTaskConfig.BeforeExitDelay.Int64)
	TaskConfig.EncodeURLWithCharset = dbTaskConfig.EncodeURLWithCharset.Bool
	TaskConfig.IgnoreKeywords = func() []string {
		var ignored []string
		if len(dbTaskConfig.IgnoreKeywords.String) == 0 {
			return ignored
		} else {
			return strings.Split(dbTaskConfig.IgnoreKeywords.String, "|")
		}
	}()
	TaskConfig.Proxy = dbTaskConfig.Proxy.String
	TaskConfig.CustomFormValues = Dm.UuidToMap(dbTaskConfig.CustomFormValuesUuid.String, "CustomFormValues")
	TaskConfig.CustomFormKeywordValues = Dm.UuidToMap(dbTaskConfig.CustomFormKeywordValuesUuid.String, "CustomFormKeywordValues")
	TaskConfig.XssPayloads = Dm.UuidToMap(dbTaskConfig.XssPayloadsUuid.String, "XssPayloads")
	return TaskConfig, nil
}

func (Dm *DbManager) GetKeyValues(uuid string, datatype int64) (map[string]interface{}, error) {
	var (
		err error
	)

	sql := `
	SELECT
	exweb_header_info.header_key, 
	exweb_header_info.header_value
	FROM
	exweb_header_info
	WHERE
	exweb_header_info.header_uuid = ?
	AND
	exweb_header_info.type = ?
	`
	values := make(map[string]interface{})
	err = Dm.Db.Select(&values, sql, uuid, datatype)
	if err != nil {
		logger.Error("get extra headers error %v", err.Error())
	}

	return nil, nil
}
