import re
script = r'''
    if (document.location.href.indexOf("default=") >= 0) {
		var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
		document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
		document.write("<option value='' disabled='disabled'>----</option>");
	}
	document.write("<option value='English'>English</option>");
	document.write("<option value='French'>French</option>");
	document.write("<option value='Spanish'>Spanish</option>");
	document.write("<option value='German'>German</option>");
    '''



highlighted = []
sources = r'''document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage'''
sinks = r'''eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location'''
# scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', response)
newLines = script.split('\n')
for lines in newLines:
    pattern = re.finditer(sources, lines)
    for grp in pattern:
        if grp:
            source = lines[grp.start():grp.end()].replace(' ', '')
            print(source)