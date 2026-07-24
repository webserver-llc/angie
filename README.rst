.. image:: misc/logo.gif
  :alt: Angie logo
  :target: https://en.angie.software/

Angie
=====

**Angie** /ˈendʒi/
is an efficient, powerful, and scalable web server
that was forked from **nginx** to act as a drop-in replacement,
so you can use existing setups
without major changes to module layout or configuration.

The project was conceived by ex-devs from the original **nginx** team
to venture beyond the earlier vision.


Getting Started
---------------

To start using **Angie**, see the official documentation in
`English <https://en.angie.software/angie/docs/>`__,
`Russian <https://angie.software/angie/docs/>`__,
`Chinese <https://cn.angie.software/angie/docs/>`__,
`Spanish <https://es.angie.software/angie/docs/>`__, or
`Portuguese <https://pt.angie.software/angie/docs/>`__:

- `Installation <https://en.angie.software/angie/docs/installation/>`_
  (`ru <https://angie.software/angie/docs/installation/>`__,
  `cn <https://cn.angie.software/angie/docs/installation/>`__,
  `es <https://es.angie.software/angie/docs/installation/>`__,
  `pt <https://pt.angie.software/angie/docs/installation/>`__)

- `Runtime configuration <https://en.angie.software/angie/docs/configuration/>`_
  (`ru <https://angie.software/angie/docs/configuration/>`__,
  `cn <https://cn.angie.software/angie/docs/configuration/>`__,
  `es <https://es.angie.software/angie/docs/configuration/>`__,
  `pt <https://pt.angie.software/angie/docs/configuration/>`__)

- `Troubleshooting and feedback channels <https://en.angie.software/angie/docs/troubleshooting/>`_
  (`ru <https://angie.software/angie/docs/troubleshooting/>`__,
  `cn <https://cn.angie.software/angie/docs/troubleshooting/>`__,
  `es <https://es.angie.software/angie/docs/troubleshooting/>`__,
  `pt <https://pt.angie.software/angie/docs/troubleshooting/>`__)

- `Development and contribution <https://en.angie.software/angie/docs/development/>`_
  (`ru <https://angie.software/angie/docs/development/>`__,
  `cn <https://cn.angie.software/angie/docs/development/>`__,
  `es <https://es.angie.software/angie/docs/development/>`__,
  `pt <https://pt.angie.software/angie/docs/development/>`__)


Features
--------

On top of all the capabilities of
`nginx 1.31.2 <https://nginx.org/en/CHANGES>`_,
**Angie** adds a number of its own advantages, including these:

Protocols & Connectivity
~~~~~~~~~~~~~~~~~~~~~~~~

- `Production-ready HTTP/3
  <https://en.angie.software/angie/docs/configuration/modules/http/http_v3/>`_
  support for both client and `proxied server
  <https://en.angie.software/angie/docs/configuration/modules/http/http_proxy/#proxy-http-version>`_
  connections, with the ability to independently use different protocol versions
  (HTTP/1.x, HTTP/2, HTTP/3) on opposite sides (nginx's HTTP/3 is limited to
  server-side and remains experimental, `suffering from degradations
  <https://en.angie.software/news/articles/http3-ebpf/>`_ after reloads).

- A built-in `DNS over HTTPS (DoH)
  <https://en.angie.software/angie/docs/configuration/modules/http/http_doh/>`_
  server module (RFC 8484) that accepts DNS queries over HTTP/HTTPS and proxies
  them to DNS server groups via UDP or TCP.

- PROXY Protocol V2 with the ability to pass arbitrary `TLV values
  <https://en.angie.software/angie/docs/configuration/modules/stream/stream_proxy/#s-proxy-protocol-tlv>`_.

- Extending authorization and balancing capabilities for `the MQTT protocol
  <https://en.angie.software/angie/docs/configuration/modules/stream/stream_mqtt_preread/>`_.

- Informing balancing decisions with `the RDP protocol's session cookies
  <https://en.angie.software/angie/docs/configuration/modules/stream/stream_rdp_preread/>`_.

- Support for the XOAUTH2 and OAUTHBEARER `authentication methods
  <https://en.angie.software/angie/docs/configuration/modules/mail/mail_smtp/#m-smtp-auth>`_
  in the mail proxy.

TLS & Certificate Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Automatic HTTPS provisions multi-domain, wildcard, and IP TLS certificates
  using built-in
  `ACME <https://en.angie.software/angie/docs/configuration/acme/>`_ with HTTP,
  DNS, and ALPN challenge support, including ACME profiles and External Account
  Binding (EAB) for commercial CAs.

- `TLS 1.3 Early Data (0-RTT)
  <https://en.angie.software/angie/docs/configuration/modules/stream/stream_ssl/#ssl-early-data>`_
  support for both HTTP and stream modules (nginx only supports HTTP).

- `Server
  <https://en.angie.software/angie/docs/configuration/modules/http/http_ssl/#ssl-ntls>`_-
  and `client-side
  <https://en.angie.software/angie/docs/configuration/modules/http/http_proxy/#proxy-ssl-ntls>`_
  support for NTLS when using the `Tongsuo
  <https://github.com/Tongsuo-Project/Tongsuo>`_ TLS library, enabled `at build
  time <https://en.angie.software/angie/docs/installation/sourcebuild/#install-source-features>`_.

Load Balancing & Upstream
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Dynamic updating of upstream groups based on events and labels from `Docker containers
  <https://en.angie.software/angie/docs/configuration/modules/http/http_docker/#http-docker>`_
  (or similar tools like Podman) without server reload.

- `Load balancing based on the average response time
  <https://en.angie.software/angie/docs/configuration/modules/http/http_upstream/#least-time>`_.
  A probability-based selection algorithm ensures smooth, balanced load
  distribution: faster servers automatically attract proportionally more
  traffic, spikes are suppressed via a configurable smoothing factor, and
  no server is ever starved of traffic. Manual weight configuration is not
  needed — and would not make sense — since traffic is distributed
  dynamically based on actual response times. Unlike nginx's approach, which
  is effectively ``least_conn`` with a time-based adjustment rather than a
  true response-time-aware algorithm, Angie's selection is driven by measured
  performance.

- `Session binding
  <https://en.angie.software/angie/docs/configuration/modules/http/http_upstream/#u-sticky>`_
  for both HTTP and stream upstreams (nginx only supports HTTP), including a
  ``learn`` mode for automatic session detection and a ``drain`` mode for
  graceful server decommissioning.

- Recommissioning upstream servers after a failure smoothly using the
  ``slow_start`` option of the `server
  <https://en.angie.software/angie/docs/configuration/modules/http/http_upstream/#u-server>`_
  directive in both HTTP and stream upstreams (nginx only supports
  ``slow_start`` for HTTP).

Observability & Monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Exposing basic information about the web server, its `configuration
  <https://en.angie.software/angie/docs/configuration/modules/http/http_api/#a-api-config-files>`_,
  as well as `metrics
  <https://en.angie.software/angie/docs/configuration/modules/http/http_api/#metrics>`_
  of proxied servers, client connections, shared memory zones, TLS certificates,
  and many other things via a RESTful `API
  <https://en.angie.software/angie/docs/configuration/modules/http/http_api/#a-api>`_
  interface in JSON format.

- Exporting statistics in `Prometheus
  <https://en.angie.software/angie/docs/configuration/modules/http/http_prometheus/#prometheus>`_
  format with `customizable templates
  <https://en.angie.software/angie/docs/configuration/modules/http/http_prometheus/#prometheus-template>`_.

- Monitoring the server through the browser with the `Console Light
  <https://en.angie.software/angie/docs/configuration/monitoring/>`_ visual
  monitoring tool.  See the online demo: https://console.angie.software/

- Arbitrarily configurable real-time statistics collection for HTTP and stream
  traffic via `the Metric module
  <https://en.angie.software/angie/docs/configuration/modules/http/http_metric/>`_,
  supporting counters, histograms, and moving averages grouped by custom keys,
  exposed via the ``/status/http/metric_zones/`` and
  ``/status/stream/metric_zones/`` API sections with Prometheus support.

- `Enhanced error logging
  <https://en.angie.software/angie/docs/configuration/modules/core/#error-log>`_
  with message filtering via the ``filter=`` parameter and
  ``error_log_user_tag`` directive, JSON format output via ``format=``, and
  a configurable maximum logging rate via the ``rate=`` parameter.

Easier Configuration & Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Several matching expressions at once in a single ``location`` directive:
  blocks with shared settings can be `combined
  <https://en.angie.software/angie/docs/configuration/modules/http/#combined-locations>`_.

- The ``goto`` directive in the rewrite module performs an
  `internal redirect to a named location
  <https://en.angie.software/angie/docs/configuration/modules/http/http_rewrite/#goto>`_
  without modifying the URI, replacing common workarounds based on ``try_files``
  or ``error_page``.

- `Automatic DNS resolver configuration
  <https://en.angie.software/angie/docs/configuration/modules/http/#resolver>`_
  from ``/etc/resolv.conf``; the file is re-read on changes, eliminating the
  need to manually specify DNS server addresses.

- The ``time_format`` directive defines a `variable with a custom time format
  <https://en.angie.software/angie/docs/configuration/modules/http/#time-format>`_,
  supporting ``strftime()``-like specifiers and ``%L`` for milliseconds.

Content & Media
~~~~~~~~~~~~~~~

- Flushing the shared memory zone in `proxy_cache_path
  <https://en.angie.software/angie/docs/configuration/modules/http/http_proxy/#proxy-cache-path>`_
  on disk preserves the cache index contents between restarts and updates,
  which eliminates the cache load delay and brings the server online even
  faster.

- Limiting the `MP4 file transfer rate
  <https://en.angie.software/angie/docs/configuration/modules/http/http_mp4/#mp4-limit-rate>`_
  proportionally to its bitrate, thus reducing the bandwidth load.

- Processing HEIC and AVIF formats and `image conversion
  <https://en.angie.software/angie/docs/configuration/modules/http/http_image_filter/#image-filter>`_.

Infrastructure
~~~~~~~~~~~~~~

- `Smooth maintenance releases
  <https://en.angie.software/angie/docs/oss_changes/>`_
  with prompt bug fixes and regular major updates with lots of new features,
  including unique features, as well as the best of nginx and freenginx.

- Pre-built `binary packages
  <https://en.angie.software/angie/docs/installation/oss_packages/#install-thirdpartymodules-oss>`_
  for many popular third-party modules.

- `Comprehensive documentation <https://en.angie.software/angie/docs/>`_
  available in multiple languages, with `full-text search
  <https://en.angie.software/search/>`_ and built-in
  `support for AI assistants
  <https://en.angie.software/angie/docs/configuration/#documentation-for-ai-assistants>`_
  via machine-readable sitemaps, per-page Markdown versions, and `Context7
  <https://context7.com/websites/en_angie_software_angie>`_ up-to-date indexing.

- A comprehensive test suite embedded directly in the source tree and
  significantly extended beyond the original nginx tests, covering all
  major subsystems with over 80% code coverage, runnable via ``make test``.
