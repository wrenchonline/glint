package dbmanager

import (
	"database/sql"
	"glint/config"
	"glint/log"
	"reflect"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type DbManager struct {
	Db *sqlx.DB
}

type DbTaskConfig struct {
	TaskId                      sql.NullInt64  `db:"TaskId"`
	FilterMode                  sql.NullString `db:"FilterMode"`
	ExtraHeadersUuid            sql.NullString `db:"ExtraHeadersUuid"`
	AllDomainReturn             sql.NullBool   `db:"AllDomainReturn"`
	SubDomainReturn             sql.NullBool   `db:"SubDomainReturn"`
	IncognitoContext            sql.NullBool   `db:"IncognitoContext"`
	NoHeadless                  sql.NullBool   `db:"NoHeadless"`
	DomContentLoadedTimeout     sql.NullInt64  `db:"DomContentLoadedTimeout"`
	TabRunTimeout               sql.NullInt64  `db:"TabRunTimeout"`
	PathByFuzz                  sql.NullBool   `db:"PathByFuzz"`
	FuzzDictPath                sql.NullString `db:"FuzzDictPath"`
	PathFromRobots              sql.NullBool   `db:"PathFromRobots"`
	MaxTabsCount                sql.NullInt64  `db:"MaxTabsCount"`
	ChromiumPath                sql.NullString `db:"ChromiumPath"`
	EventTriggerMode            sql.NullString `db:"EventTriggerMode"`
	EventTriggerInterval        sql.NullInt64  `db:"EventTriggerInterval"`
	BeforeExitDelay             sql.NullInt64  `db:"BeforeExitDelay"`
	EncodeURLWithCharset        sql.NullBool   `db:"EncodeURLWithCharset"`
	IgnoreKeywords              sql.NullString `db:"IgnoreKeywords"`
	Proxy                       sql.NullString `db:"Proxy"`
	CustomFormValuesUuid        sql.NullString `db:"CustomFormValuesUuid"`
	CustomFormKeywordValuesUuid sql.NullString `db:"CustomFormKeywordValuesUuid"`
	XssPayloadsUuid             sql.NullString `db:"XssPayloadsUuid"`
}

type ExtraHeaders struct {
	Key   string `db:"key"`
	Value string `db:"value"`
}

//Init 初始化mysql数据库
func (Dm *DbManager) Init() error {
	//构建连接："用户名:密码@tcp(IP:端口)/数据库?charset=utf8"
	path := strings.Join([]string{config.UserName, ":", config.Password, "@tcp(", config.Ip, ":", config.Port, ")/", config.DbName, "?charset=utf8"}, "")
	//打开数据库,前者是驱动名，所以要导入： _ "github.com/go-sql-driver/mysql"
	DB, err := sqlx.Connect("mysql", path)
	DB.SetMaxOpenConns(20)
	DB.SetMaxIdleConns(10)
	if err != nil {
		log.Debug("open database fail")
		return err
	}
	log.Debug("connnect success")
	Dm.Db = DB
	return nil
}

//GetTaskConfig 根据任务ID获取数据库的扫描配置
func (Dm *DbManager) GetTaskConfig(taskid int) (DbTaskConfig, error) {
	sql := `
	SELECT
	task_config.*
	FROM
		task_config
	WHERE
		task_config.TaskId = ?
	`
	values := DbTaskConfig{}
	err := Dm.Db.Get(&values, sql, taskid)
	if err != nil {
		log.Error(err.Error())
	}
	return values, err
}

//GetExtraHeaders 根据Uuid获取数据库的扫描头
func (Dm *DbManager) GetExtraHeaders(uuid string) ([]ExtraHeaders, error) {
	sql := `
	SELECT
	headers_uuid.key, 
	headers_uuid.value
	FROM
		headers_uuid
	WHERE
	headers_uuid.uuid = ?`
	values := []ExtraHeaders{}
	err := Dm.Db.Select(&values, sql, uuid)
	if err != nil {
		log.Error(err.Error())
	}
	return values, err
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
	switch type_name {
	case "Headers":
		ExtraHeaders, err := Dm.GetExtraHeaders(uuid)
		if err != nil {
			log.Error(err.Error())
		}
		for _, Header := range ExtraHeaders {
			converted = Dm.ConvertToMap(Header, converted)
		}
	}
	return converted
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
	TaskConfig.IgnoreKeywords = strings.Split(dbTaskConfig.IgnoreKeywords.String, "|")
	TaskConfig.Proxy = dbTaskConfig.Proxy.String
	TaskConfig.CustomFormValues = Dm.UuidToMap(dbTaskConfig.CustomFormValuesUuid.String, "CustomFormValues")
	TaskConfig.CustomFormKeywordValues = Dm.UuidToMap(dbTaskConfig.CustomFormKeywordValuesUuid.String, "CustomFormKeywordValues")
	TaskConfig.XssPayloads = Dm.UuidToMap(dbTaskConfig.XssPayloadsUuid.String, "XssPayloads")
	return TaskConfig, nil
}
