
VER=	$(shell grep 'define ANGIE_VERSION' src/core/angie.h		\
		| sed -e 's/^.*"\(.*\)".*/\1/')
XSLS?=	xslscript.pl


all:		changes

changes:	CHANGES.ru						\
		CHANGES

	hg ci -m "Generated changes for $(VER) release."

.PHONY:	all changes


CHANGES.ru:	docs/dtd/changes.dtd					\
		docs/xml/angie/changes.xml				\
		docs/xml/change_log_conf.xml				\
		docs/xslt/changes.xslt

	xmllint --noout --valid docs/xml/angie/changes.xml
	xsltproc --stringparam lang ru					\
		-o $@ docs/xslt/changes.xslt docs/xml/angie/changes.xml


CHANGES:	docs/dtd/changes.dtd					\
		docs/xml/angie/changes.xml				\
		docs/xml/change_log_conf.xml				\
		docs/xslt/changes.xslt

	xmllint --noout --valid docs/xml/angie/changes.xml
	xsltproc --stringparam lang en					\
		-o $@ docs/xslt/changes.xslt docs/xml/angie/changes.xml


docs/xslt/changes.xslt:		docs/xsls/changes.xsls

	$(XSLS) -o $@ $<
