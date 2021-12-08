package dbmanager

import (
	"glint/config"
	"glint/log"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type DbManager struct {
	Db *sqlx.DB
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
func (Dm *DbManager) GetTaskConfig(taskid int) ([]interface{}, error) {
	sql := `
	SELECT
	task_config.*
	FROM
		task_config
	WHERE
		task_config.TaskId = ?
	`
	var values []interface{}
	err := Dm.Db.Select(&values, sql, taskid)
	if err != nil {
		log.Error(err.Error())
	}
	return values, err
}
