#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/8 10:07 AM
# @Author  : w8ay
# @File    : htmlparser.py
import random
from abc import ABC

from html.parser import HTMLParser

import pyjsparser

from jscontext import analyse_js


def random_upper(text: str):
    '''
    将文本随机大写翻转
    :param text:
    :return:
    '''
    length = len(text)
    for i in range(length // 2):
        rand = random.randint(0, length - 1)
        while text[rand].isupper():
            rand = random.randint(0, length - 1)
        temp = text[rand].upper()
        text = text[0:rand] + temp + text[rand + 1:]
    return text


class MyHTMLParser(HTMLParser, ABC):
    def __init__(self):
        super().__init__()
        self.tree = []
        self.tokenizer = []
        self.root = None
        temp = {
            "tagname": "",
            "content": "",
            "attibutes": []
        }

    def handle_starttag(self, tag, attrs):
        if len(self.tree) == 0:
            self.root = tag
        self.tree.append(
            {
                "tagname": tag,
                "content": "",
                "attibutes": attrs
            }
        )

    def handle_endtag(self, tag):
        if len(self.tree) > 0:
            r = self.tree.pop()
            self.tokenizer.append(r)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data):
        if self.tree:
            self.tree[-1]["content"] += data

    def handle_comment(self, data):
        self.tokenizer.append({
            "tagname": "#comment",
            "content": data,
            "attibutes": []
        })

    def getTokenizer(self):
        while len(self.tree):
            r = self.tree.pop()
            self.tokenizer.append(r)
        return self.tokenizer


def getParamsFromHtml(html):
    parse = MyHTMLParser()
    parse.feed(html)
    tokens = parse.getTokenizer()
    result = set()
    for token in tokens:
        tagname = token["tagname"].lower()
        if tagname == "input":
            for attibute in token["attibutes"]:
                key, value = attibute
                if key == "name":
                    result.add(value)
                    break
        elif tagname == "script":
            content = token["content"]
            try:
                nodes = pyjsparser.parse(content).get("body", [])
            except pyjsparser.pyjsparserdata.JsSyntaxError as e:
                return []
            result |=set(analyse_js(nodes))
    return list(result)


def SearchInputInResponse(input, body):
    parse = MyHTMLParser()
    parse.feed(body)
    tokens = parse.getTokenizer()
    index = 0
    occurences = []
    for token in tokens:
        tagname = token["tagname"]
        content = token["content"]
        attibutes = token["attibutes"]
        _input = input
        origin_length = len(occurences)

        if _input in tagname:
            occurences.append({
                "type": "intag",
                "position": index,
                "details": token,
            })
        elif input in content:
            if tagname == "#comment":
                occurences.append({
                    "type": "comment",
                    "position": index,
                    "details": token,
                })
            elif tagname == "script":
                occurences.append({
                    "type": "script",
                    "position": index,
                    "details": token,
                })
            elif tagname == "style":
                occurences.append({
                    "type": "html",
                    "position": index,
                    "details": token,
                })
            else:
                occurences.append({
                    "type": "html",
                    "position": index,
                    "details": token,
                })
        else:
            # 判断是在name还是value上
            for k, v in attibutes:
                content = None
                if _input in k:
                    content = "key"
                elif v and _input in v:
                    content = "value"

                if content:
                    occurences.append({
                        "type": "attibute",
                        "position": index,
                        "details": {"tagname": tagname, "content": content, "attibutes": [(k, v)]},
                    })
        if len(occurences) > origin_length:
            index += 1
    return occurences

html = """<html><head>
<script src="javascript/jquery-1.11.1.min.js" type="text/javascript"></script>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
<script type="text/javascript">
	function loadTest() {
		var id = myfunc("id");
		//location.href = '/index/xssTest.do?id='+id;
		var id = myfunc("id");
		$.ajax({
			url : "/index/xssTest.do",
			type : "GET",
			dataType : "html",
			data : {
				id : id
			},
			success : function(data) {
				$('#xss').html(data);
			}
		});

	}
	function test() {
		$('#xss').html($("#testName").val());
	}

	var myfunc = function(key) {
		var url = window.location.href;//首先获取url
		if (url.indexOf("?") != -1) { //判断是否有参数
			var strSub = null;
			var str = url.split("?");//根据？截取url
			var strs = str[1].split("&");//str[1]为获取？号后的字符串，并且根据&符号进行截取，得到新的字符串数组，这个字符串数组中有n个key=value字符串
			for (var i = 0; i < strs.length; i++) {//遍历字符串数组
				strSub = strs[i].split("=");//取第i个key=value字符串，并用“=”截取获得新的字符串数组 这个数组里面第0个字符是key，第1个字符value
				if (strSub[0] == key) {//判断第0个字符与该方法的参数key是否相等，如果相等 则返回对应的值value。
					return strSub[1];
				}
			}
		}
		return "";
	}
</script>
</head>
<body onload="loadTest()">
	<input id="testName" name="testName">
	<button onclick="test()">提交</button>
	<div id="xss">bKUYKDOrptng</div>

</body></html>"""

print(SearchInputInResponse("bKUYKDOrptng",html))