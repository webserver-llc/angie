
VER=	$(shell grep 'define ANGIE_VERSION' src/core/angie.h		\
		| sed -e 's/^.*"\(.*\)".*/\1/')
ANGIE=	angie-$(VER)
TEMP=	tmp
XSLS?=	xslscript.pl


all:		changes

changes:	$(TEMP)/$(ANGIE)/CHANGES.ru				\
		$(TEMP)/$(ANGIE)/CHANGES


$(TEMP)/$(ANGIE)/CHANGES.ru:	docs/dtd/changes.dtd			\
				docs/xml/angie/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	mkdir -p $(TEMP)/$(ANGIE)

	xmllint --noout --valid docs/xml/angie/changes.xml
	xsltproc --stringparam lang ru					\
		-o $@ docs/xslt/changes.xslt docs/xml/angie/changes.xml


$(TEMP)/$(ANGIE)/CHANGES:	docs/dtd/changes.dtd			\
				docs/xml/angie/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	mkdir -p $(TEMP)/$(ANGIE)

	xmllint --noout --valid docs/xml/angie/changes.xml
	xsltproc --stringparam lang en					\
		-o $@ docs/xslt/changes.xslt docs/xml/angie/changes.xml


docs/xslt/changes.xslt:		docs/xsls/changes.xsls

	$(XSLS) -o $@ $<
