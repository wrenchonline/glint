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


controlledVariables = set()
highlighted = []
sources = r'''document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage'''
sinks = r'''eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location'''
# scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', response)
newLines = script.split('\n')
for lines in newLines:
    parts = lines.split('var ')
    pattern = re.finditer(sources, lines)
    for grp in pattern:
        if grp:
            source = lines[grp.start():grp.end()].replace(' ', '')
            if source:
                if len(parts) > 1:
                    for part in parts:
                        if source in part:
                            controlledVariables.add(re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]+', part).group().replace('$', '\$'))
                            print(controlledVariables)