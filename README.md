# webscan
webscan 是一款golang开发的web漏洞主动(被动)扫描器，如有一下功能:

1.xss AST语义检测 

2.SQL 注入 

3.xray poc 脚本检测（这个偷懒主要参照 https://github.com/jweny/pocassist 
)

4.基于浏览器的爬虫url收集，添加类似反链功能记录，适用于xss这类payload无法一次回显判断的情况。 

本项目以实战为主，有很多改进的处理:
1.发包手段和主动爬虫基于基于浏览器chromedp开发，有许多意外惊喜（指js）
2.payload 注重过waf处理，许多构造手段在网上搜罗。


