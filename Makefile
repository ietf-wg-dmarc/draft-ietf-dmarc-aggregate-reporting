MMARK=/usr/bin/mmark
#XML2RFC=/usr/local/bin/xml2rfc
XML2RFC=/usr/bin/xml2rfc
SOURCES=draft-ietf-dmarc-aggregate-reporting-25.md
XML=$(SOURCES:.md=.xml)
TXT=$(SOURCES:.md=.txt)

all: $(XML) $(TXT)

%.xml : %.md dmarc-xml-0.2.xml dmarc-xml-0.2.xsd
	#$(MMARK) -xml2 -page $< > $@ 
	$(MMARK) $< > $@ 
	
%.txt : %.xml
	$(XML2RFC) $< --text

clean:
	rm $(XML)
	rm $(TXT)
