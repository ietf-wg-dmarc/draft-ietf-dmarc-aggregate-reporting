MMARK=/usr/bin/mmark
#XML2RFC=/usr/local/bin/xml2rfc
XML2RFC=/usr/bin/xml2rfc
SOURCES=draft-ietf-dmarc-aggregate-reporting-21.md
XML=$(SOURCES:.md=.xml)
TXT=$(SOURCES:.md=.txt)

all: $(XML) $(TXT)

%.xml : %.md
	#$(MMARK) -xml2 -page $< > $@ 
	$(MMARK) $< > $@ 
	
%.txt : %.xml
	$(XML2RFC) $< --text

clean:
	rm $(XML)
	rm $(TXT)
