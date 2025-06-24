
VER =		$(shell grep 'define ANGIE_VERSION' src/core/angie.h	\
			| sed -e 's/^.*"\(.*\)".*/\1/')
ANGIE =		angie-$(VER)
TEMP =		tmp

CC =		cl
OBJS =		objs.msvc8
OPENSSL =	openssl-3.5.0
ZLIB =		zlib-1.3.1
PCRE =		pcre2-10.45


release: export

	mv $(TEMP)/$(ANGIE)/docs/txt/README $(TEMP)/$(ANGIE)
	rm $(TEMP)/$(ANGIE)/README.rst
	rm -r $(TEMP)/$(ANGIE)/docs
	rm -r $(TEMP)/$(ANGIE)/misc

	tar -c -z -f $(ANGIE).tar.gz --directory $(TEMP) $(ANGIE)


export:
	rm -rf $(TEMP)
	hg archive -X '.hg*' -X '.git*' $(TEMP)/$(ANGIE)


RELEASE:
	hg tag -m "Angie-$(VER) release tag." Angie-$(VER)

	$(MAKE) -f misc/GNUmakefile release


win32:
	./auto/configure						\
		--with-cc=$(CC)						\
		--builddir=$(OBJS)					\
		--with-debug						\
		--prefix= 						\
		--conf-path=conf/nginx.conf				\
		--pid-path=logs/nginx.pid				\
		--http-log-path=logs/access.log				\
		--error-log-path=logs/error.log				\
		--sbin-path=nginx.exe					\
		--http-client-body-temp-path=temp/client_body_temp	\
		--http-proxy-temp-path=temp/proxy_temp			\
		--http-fastcgi-temp-path=temp/fastcgi_temp		\
		--http-scgi-temp-path=temp/scgi_temp			\
		--http-uwsgi-temp-path=temp/uwsgi_temp			\
		--with-cc-opt=-DFD_SETSIZE=1024				\
		--with-pcre=$(OBJS)/lib/$(PCRE)				\
		--with-zlib=$(OBJS)/lib/$(ZLIB)				\
		--with-http_v2_module					\
		--with-http_realip_module				\
		--with-http_addition_module				\
		--with-http_sub_module					\
		--with-http_dav_module					\
		--with-http_stub_status_module				\
		--with-http_flv_module					\
		--with-http_mp4_module					\
		--with-http_gunzip_module				\
		--with-http_gzip_static_module				\
		--with-http_auth_request_module				\
		--with-http_random_index_module				\
		--with-http_secure_link_module				\
		--with-http_slice_module				\
		--with-mail						\
		--with-stream						\
		--with-stream_realip_module				\
		--with-stream_ssl_preread_module			\
		--with-openssl=$(OBJS)/lib/$(OPENSSL)			\
		--with-openssl-opt="no-asm no-tests no-makedepend	\
			-D_WIN32_WINNT=0x0501"				\
		--with-http_ssl_module					\
		--with-mail_ssl_module					\
		--with-stream_ssl_module


zip: export
	rm -f $(ANGIE).zip

	mkdir -p $(TEMP)/$(ANGIE)/docs.new
	mkdir -p $(TEMP)/$(ANGIE)/logs
	mkdir -p $(TEMP)/$(ANGIE)/temp

	sed -i '' -e "s/$$/`printf '\r'`/" $(TEMP)/$(ANGIE)/conf/*

	mv $(TEMP)/$(ANGIE)/docs/txt/README $(TEMP)/$(ANGIE)/docs.new

	rm -r $(TEMP)/$(ANGIE)/docs
	mv $(TEMP)/$(ANGIE)/docs.new $(TEMP)/$(ANGIE)/docs

	cp -p $(OBJS)/nginx.exe $(TEMP)/$(ANGIE)

	$(MAKE) -f docs/GNUmakefile changes
	mv $(TEMP)/$(ANGIE)/CHANGES* $(TEMP)/$(ANGIE)/docs/

	cp -p $(OBJS)/lib/$(OPENSSL)/LICENSE.txt			\
		$(TEMP)/$(ANGIE)/docs/OpenSSL.LICENSE

	cp -p $(OBJS)/lib/$(PCRE)/LICENCE				\
		$(TEMP)/$(ANGIE)/docs/PCRE.LICENCE

	sed -ne '/^ (C) 1995-20/,/^  jloup@gzip\.org/p'			\
		$(OBJS)/lib/$(ZLIB)/README				\
		> $(TEMP)/$(ANGIE)/docs/zlib.LICENSE

	touch -r $(OBJS)/lib/$(ZLIB)/README				\
		$(TEMP)/$(ANGIE)/docs/zlib.LICENSE

	rm -r $(TEMP)/$(ANGIE)/auto
	rm -r $(TEMP)/$(ANGIE)/misc
	rm -r $(TEMP)/$(ANGIE)/src

	cd $(TEMP) && zip -r ../$(ANGIE).zip $(ANGIE)


icons:	src/os/win32/nginx.ico

# 48x48, 32x32 and 16x16 icons

src/os/win32/nginx.ico:	src/os/win32/nginx_icon48.xpm			\
			src/os/win32/nginx_icon32.xpm			\
			src/os/win32/nginx_icon16.xpm

	test -d $(TEMP) || mkdir $(TEMP)

	xpmtoppm --alphaout=$(TEMP)/nginx48.pbm				\
		src/os/win32/nginx_icon48.xpm > $(TEMP)/nginx48.ppm

	xpmtoppm --alphaout=$(TEMP)/nginx32.pbm				\
		src/os/win32/nginx_icon32.xpm > $(TEMP)/nginx32.ppm

	xpmtoppm --alphaout=$(TEMP)/nginx16.pbm				\
		src/os/win32/nginx_icon16.xpm > $(TEMP)/nginx16.ppm

	ppmtowinicon -output src/os/win32/nginx.ico -andpgms		\
		$(TEMP)/nginx48.ppm $(TEMP)/nginx48.pbm			\
		$(TEMP)/nginx32.ppm $(TEMP)/nginx32.pbm			\
		$(TEMP)/nginx16.ppm $(TEMP)/nginx16.pbm
