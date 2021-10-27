package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	log "wenscan/Log"
	"wenscan/Xss"
	ast "wenscan/ast"
	cf "wenscan/config"
	http "wenscan/http"

	"github.com/fatih/color"
	"github.com/k0kubun/go-ansi"
	. "github.com/logrusorgru/aurora"
	"github.com/mitchellh/colorstring"
	"github.com/thoas/go-funk"
)

func TestXSS(t *testing.T) {
	log.DebugEnable(false)
	playload := Xss.RandStringRunes(12)
	Spider := http.Spider{}
	Spider.Init()
	var locationDS []ast.Occurence
	defer Spider.Close()
	c := cf.Conf{}
	//读取配置文件
	conf := c.GetConf()
	Spider.ReqMode = conf.ReqMode
	// if err := Spider.SetCookie(conf); err != nil {
	// 	panic(err)
	// }

	jsonFile, err := os.Open("result.json")

	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var JsonUrls []ast.JsonUrl
	err = json.Unmarshal([]byte(byteValue), &JsonUrls)
	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}

	for _, data := range JsonUrls {
		Spider.ReqMode = data.MetHod
		Spider.Url, err = url.Parse(data.Url)
		Spider.PostData = []byte(data.Data)
		Spider.Headers = data.Headers
		color.Red(Spider.Url.String())
		if err != nil {
			color.Red(err.Error())
		}
		if Spider.CheckPayloadNormal(playload, func(html string) bool {
			locations := ast.SearchInputInResponse(playload, html)
			if len(locations) != 0 {
				locationDS = locations
				return true
			}
			return false
		}) {
			var result interface{}
			VulOK := false
			result = funk.Map(locationDS, func(item ast.Occurence) bool {
				if item.Type == "html" {
					g := new(Xss.Generator)
					g.GeneratorPayload(Xss.Htmlmode, playload, item)
					for {
						Spider.PostData = []byte(data.Data)
						newpayload, methods := g.GetPayloadValue()
						if len(newpayload) != 0 {
							if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
								locations := ast.SearchInputInResponse(playload, html)
								if g.CheckXssVul(locations, methods, Spider) {
									log.Info("Xss::html标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
									return true
								}
								return false
							}) {
								break
							}
						} else {
							break
						}
					}
				} else if item.Type == "attibute" {
					//假设如果渲染得值在key中
					if item.Details.Content == "key" {
						g := new(Xss.Generator)
						g.GeneratorPayload(Xss.Attibute, playload, item)
						for {
							Spider.PostData = []byte(data.Data)
							newpayload, methods := g.GetPayloadValue()
							if len(newpayload) != 0 {
								if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
									locations := ast.SearchInputInResponse(playload, html)
									if g.CheckXssVul(locations, methods, Spider) {
										log.Info("Xss::attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
										return true
									}
									return false
								}) {
									break
								}
							} else {
								break
							}
						}
					} else {
						//否则就在value中
						g := new(Xss.Generator)
						g.GeneratorPayload(Xss.Attibute, playload, item)
						for {
							Spider.PostData = []byte(data.Data)
							newpayload, methods := g.GetPayloadValue()
							if len(newpayload) != 0 {
								if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
									locations := ast.SearchInputInResponse(playload, html)
									if g.CheckXssVul(locations, methods, Spider) {
										log.Info("Xss::attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
										return true
									}
									return false
								}) {
									break
								}
							} else {
								break
							}
						}
					}
				} else if item.Type == "script" {
					g := new(Xss.Generator)
					g.GeneratorPayload(Xss.Script, playload, item)
					for {
						Spider.PostData = []byte(data.Data)
						newpayload, methods := g.GetPayloadValue()
						if len(newpayload) != 0 {
							if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
								locations := ast.SearchInputInResponse(playload, html)
								if g.CheckXssVul(locations, methods, Spider) {
									log.Info("Xss::script标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
									return true
								}
								return false
							}) {
								break
							}
						} else {
							break
						}
					}
				}
				return VulOK
			})

			if funk.Contains(result, true) {
				//log.Info("html标签可被闭合")
			}
		}
	}

}

func Test_JS(t *testing.T) {

	io := ansi.NewAnsiStdout()
	log.DebugEnable(true)
	var sourceFound bool
	var sinkFound bool
	script := `
	var userTable;/*用户列表*/
	require( ['tools','fancybox'], function(tools,fancybox) {
		var hasLock = hasAuth('user:lock'),
			 hasEdit = hasAuth('user:edit'),
			 hasDel = hasAuth('user:del'),
			 hasInitpwd = hasAuth('user:initpwd');
		var table;
		var form;
		var fancyClose=".fancybox-close";
		var editUserFancyFlag = false;
		layui.use(['form','table'], function() {
			form = layui.form;
			table = layui.table;
			$ = layui.jquery;
			$(document).keyup(function(event){
				if(event.keyCode ==13){
					$('#searchBtn').click();
				}
			});
			/*用户列表*/
			userTable = table.render({
				id: 'userTable',
				elem: '#userList',
				url:basePath+'sys/user/userList.do',
				where:{hostIp:$('#search_host_ip').val()},
				cellMinWidth: 80,/*全局定义常规单元格的最小宽度，layui 2.2.1 新增*/
				skin: 'line',
				cols: [[
					{type: 'checkbox', title: '全选', event:'check'},
					{field:'userName', title: '用户名', align:'center', sort: true},
					{field:'roleName', title: '角色', align:'center'},
					{field:'isLock', title: '状态', align:'center', sort: true, templet: function(data) {
						if (data.isLock == 1) {
							return '锁定';
						}
						return '正常';
					}},
					{field:'userDesc', title: '描述', width:320},
					{field:'', title: '操作', align:'center', width:220, templet: function(data) {
	//			    	if(data.isSystem == 1){
	//			    		return "";
	//			    	}
						var str = '<div class="operateBtn">';
						if(hasLock){
							if(data.isLock == 1){
								$.ajax({
									type:"POST",
									url:basePath+'sys/data/getDataByKey.do',
									dataType:'json',
									async: false,
									data:{
										dataKey:'lockTimes',
										dataType:'userLockParam'
									},
									success:function(data1){
										var loginTime = data.userLoginTime;
										var loginDate;
										var t = Date.parse(loginTime);
										if (!isNaN(t)) {
											loginDate = new Date(Date.parse(loginTime.replace(/-/g, "/")));
										} else {
											loginDate = new Date();
										}
										if(loginDate.getTime()<(new Date().getTime()-data1.dataValue * 60 * 1000)){
											/* 自动解锁更新到数据库*/
											$.ajax({
												type:"POST",
												url:basePath+'sys/user/lockUser.do',
												dataType:'json',
												data:{userId:data.userId, isLock:0},
												success:function(data){
													
												}
											});
											str += '<a href="javascript:void(0);" lay-event="lock" title="锁定用户" class="unLockBtn"><i class="icon iconfont"></i></a>';
										}else{
											str += '<a href="javascript:void(0);" lay-event="lock" title="解锁用户" class="lockBtn"><i class="icon iconfont"></i></a>';
										}
									},
									error:function(data){
										tools.loadTips("error",error(data));
									}
								});
							} else {
								str += '<a href="javascript:void(0);" lay-event="lock" title="锁定用户" class="unLockBtn"><i class="icon iconfont"></i></a>';
							}
						}
						if(hasEdit){
							str += '<a href="'+basePath+'sys/user/userEdit.do?userId='+data.userId+'" lay-event="edit" title="编辑用户" class="editBtn editUserBtn"><i class="icon iconfont"></i></a>';
						}
						if(hasDel){
							str += '<a href="javascript:void(0);" lay-event="del" title="删除用户" class="deleteBtn"><i class="icon iconfont"></i></a>';
						}
						if(hasInitpwd){
							str += '<a href="javascript:void(0);" lay-event="init" title="初始化密码" class="initPwdBtn"><i class="icon iconfont"></i></a>';
						}
						str += '</div>';
						return str;
					}},
				]],
				page: {/*支持传入 laypage 组件的所有参数（某些参数除外，如：jump/elem） - 详见文档*/
					layout: ['count', 'prev', 'page', 'next', 'skip'],/*自定义分页布局*/
					limit:10,
					limits:[10,20,50],
					groups: 5,
				},
				done:function(res){
					if($(".editUserBtn").length && !editUserFancyFlag){
						$(".editUserBtn").fancybox({
							width : 750,
							maxHeight: 600,
							type: 'iframe',
							title:null,
							scrolling:'none',
							closeBtn:true,
							autoResize:true,
							preload:false,
							helpers:{
								overlay:{
									closeClick:false
								}
							},
							afterShow:function(e){
								var f_close=$(".fancybox-close");
								var _document=$(window.frames["fancybox-frame"].document);
								_document.find(".fanceClose").click(function(){
									f_close.click();
								});
							}
						});
						editUserFancyFlag = true;
					};
				}
			});
			$('#searchBtn').on('click', function(){
				userTable.reload({
					page:{curr:1},
					where:{
						userName: $("input[name='userName']").val(),
					}
				});
			});
			$('#search_userName').bind('keyup', function(event) {
				if (event.keyCode == "13") {
					$('#searchUserInfo').click();
				}
			});
			/*监听工具条*/
			table.on('tool(userListFilter)', function(obj){
				var data = obj.data;
				if(obj.event == 'del'){
					if(data.isSystem != 1){
						tools.getPromit("confirm","alert","您确认要删除选中用户吗?","delUser",'modal-sm','',function(){
							$.ajax({
								type:"POST",
								url:basePath+'sys/user/deleteUser.do',
								dataType:'json',
								data:{userIds:data.userId},
								success:function(data){
									tools.loadTips(data.type,data.content);
									userTable.reload();
								},
								error:function(data){
									tools.loadTips("error",error(data));
								}
							});
						});
						$('#delUser').modal({
							backdrop:'static',
							keyboard:false
						})
						$('#delUser').modal('show');
					}else{
						tools.loadTips('alert','系统用户不可删除！');
					}
				}else if(obj.event == 'init'){
					tools.getPromit("confirm","alert","您确定要初始化选中用户的密码吗?","initPwd",'modal-sm','',function(){
						/*初始化后回调*/
						$.ajax({
							type:"POST",
							url:basePath+'sys/user/initPwd.do',
							dataType:'json',
							data:{userId:data.userId},
							success:function(data){
								tools.loadTips(data.type,data.content);
								userTable.reload();
							},
							error:function(data){
								tools.loadTips("error",error(data));
							}
						});
					});
					$('#initPwd').modal({
						backdrop:'static',
						keyboard:false
					})
				}else if(obj.event == 'lock'){
					var optText = '';
					var isLock = 0;
					if(data.isLock == 1){
						optText = "解锁";
						isLock = 0;
					}else{
						optText = "加锁";
						isLock = 1;
					}
					tools.getPromit("confirm","alert","您确定要"+optText+"选中用户吗?","lockUser",'modal-sm','',function(){
						/*初始化后回调*/
						$.ajax({
							type:"POST",
							url:basePath+'sys/user/lockUser.do',
							dataType:'json',
							data:{userId:data.userId, isLock:isLock},
							success:function(data){
								tools.loadTips(data.type,data.content);
								userTable.reload();
							},
							error:function(data){
								tools.loadTips("error",error(data));
							}
						});
					});
					$('#lockUser').modal({
						backdrop:'static',
						keyboard:false
					})
				}
			});
			/*编辑用户提交*/
			form.render();
			form.on('submit(editUserForm)', function(data){
				$.ajax({
					type:"POST",
					url:basePath+'sys/user/editUser.do',
					dataType:'json',
					data:$(data.form).serialize(),
					success:function(data){
						window.parent.userTable.reload();
						tools.loadTips(data.type,data.content,function(){
							window.parent.$(fancyClose).click();
						});
					},
					error:function(data){
						tools.loadTips("error",error(data));
					}
				});
			});
			/*添加用户提交*/
			form.on('submit(addUserForm)', function(data){
				$.ajax({
					type:"POST",
					url:basePath+'sys/user/addUser.do',
					dataType:'json',
					async:false,
					data:$(data.form).serialize(),
					success:function(data){
						tools.loadTips(data.type,data.content,function(){
							window.parent.userTable.reload();
							window.parent.$(fancyClose).click();
						});
					},
					error:function(data){
						tools.loadTips("error",error(data));
					}
				});
			});
			/*锁定设置提交*/
			form.on('submit(userLockParamForm)', function(data){
				var p_elem=$(this).parents(".modal-content").find(".formPanelBox");
				p_elem.find(".mustChecks .checks").each(function(index, el) {
					var check_inp=$(this).find("input[type='checkbox']");
					var check_inp_next=check_inp.next(".layui-unselect");
					if(check_inp_next.hasClass('layui-form-checked')){
						check_inp_next.next().val(1);
					}else{
						check_inp_next.next().val(0);
					}
				});
				$.ajax({
					type:"POST",
					url:basePath+'sys/user/editLockSet.do',
					dataType:'json',
					async:false,
					data:$(data.form).serialize(),
					success:function(data){
						tools.loadTips(data.type,data.content,function(){
							tools.fancyboxClose();
						});
					},
					error:function(data){
						tools.loadTips("error",error(data));
					}
				});
			});
			/*密码修改*/
			form.on('submit(editPwdForm)', function(data){
				$.ajax({
					type:"POST",
					url:basePath+'sys/user/editPwd.do',
					dataType:'json',
					data:$("#editPwdForm").serialize(),
					success:function(data){
						if(data.type == 'success'){
							tools.loadTips(data.type,data.content,function(){
								window.parent.$(fancyClose).click();
							});
						}else{
							tools.loadTips(data.type,data.content);
						}
					},
					error:function(data){
						tools.loadTips("error",error(data));
					}
				});
			});
			form.verify({
				/*验证用户名是否重复*/
				userNameUnique: function(value, item) {
					var userName = value.trim();
					var checkResult='';
					$.ajax({
						url : basePath+'sys/user/checkUserName.do',
						type : 'POST',
						data : {"userName" : userName},
						datatype : 'json',
						async : false,
						success : function(data) {
							if (data.type == 'success') {
								checkResult = data.content;
							}
						},
						error:function(data){
							tools.loadTips("error",error(data));
						}
					});
					return checkResult;
				},
				/*验证密码是否符合设定标准*/
				userPwd: function(value) {
					var userPwd = value.trim();
					var checkResult='';
					if(userPwd != ''){
						$.ajax({
							url : basePath+'sys/user/checkUserPwd.do',
							type : 'POST',
							data : {"userPwd" : userPwd},
							datatype : 'json',
							async : false,
							success : function(data) {
								if (data.type == 'error') {
									checkResult = data.content;
								}
							},
							error:function(data){
								tools.loadTips("error",error(data));
							}
						});
					}
					return checkResult;
				},
				/*验证密码是否一致(密码修改)*/
				userPwdSame: function(value, item) {
					var confirmNewPwd = value.trim();
					var newPwd = $('#newPwd').val();
					var checkResult='';
					if(confirmNewPwd != newPwd){
						checkResult = '密码不一致！';
					}
					return checkResult;
				}
			});
		});
		/*新增用户*/
		if($(".addUserBtn").length){
			$(".addUserBtn").fancybox({
				width : 650,
				maxHeight: 550,
				type: 'iframe',
				title:null,
				scrolling:'none',
				closeBtn:true,
				autoResize:true,
				preload:false,
				helpers:{
					overlay:{
						closeClick:false
					}
				},
				afterShow:function(e){
					var f_close=$(".fancybox-close");
					var _document=$(window.frames["fancybox-frame"].document);
					_document.find(".fanceClose").click(function(){
						f_close.click();
					});
				}
			});
		}
		/*锁定设置*/
		if($(".lockSetBtn").length){
			$(".lockSetBtn").fancybox({
				width : 750,
				maxHeight: 550,
				type: 'iframe',
				title:null,
				scrolling:'none',
				closeBtn:true,
				autoResize:true,
				preload:false,
				helpers:{
					overlay:{
						closeClick:false
					}
				},
				afterShow:function(e){
					var f_close=$(".fancybox-close");
					var _document=$(window.frames["fancybox-frame"].document);
					_document.find(".fanceClose").click(function(){
						f_close.click();
					});
				}
			});
		}
		/*菜单栏添加选中样式*/
		$("#system").addClass("on");
		$("#user").addClass("on");
	});
	`
	sources := `document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage`
	sinks := `eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location`
	newlines := strings.Split(script, "\n")

	matchsinks := funk.Map(newlines, func(x string) string {
		//parts := strings.Split(x, "var ")
		r, _ := regexp.Compile(sinks)
		C := r.FindAllStringSubmatch(x, -1)
		if len(C) != 0 {
			fmt.Println(Sprintf(Magenta("sinks match :%v \n"), Red(C[0][0])))
			return "vul"
		}
		return ""
	})

	matchsources := funk.Map(newlines, func(x string) string {
		r, _ := regexp.Compile(sources)
		C := r.FindAllStringSubmatch(x, -1)
		if len(C) != 0 {
			fmt.Println(Sprintf(Magenta("sources match :%v \n"), Yellow(C[0][0])))
			return "vul"
		}
		return ""
	})

	if value, ok := matchsources.([]string); ok {
		if funk.Contains(value, "vul") {
			sourceFound = true
		}
	}

	if value, ok := matchsinks.([]string); ok {
		if funk.Contains(value, "vul") {
			sinkFound = true
		}
	}

	if sourceFound && sinkFound {
		colorstring.Fprintf(io, "[red] 发现DOM XSS漏洞，该对应参考payload代码应由研究人员构造 \n")
	}

	// ast, err := js.Parse(parse.NewInputString(script))
	// if err != nil {
	// 	t.Error(err.Error())
	// }

	// for _, v := range ast.Declared {
	// 	fmt.Println(Sprintf(Magenta("ast.Declared:%s"), Blue(string(v.Data))))
	// }

	// for _, v := range ast.List {
	// 	v.
	// }
	// fmt.Println("JS:", ast.String())
}
