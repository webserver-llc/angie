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
`nginx 1.27 <https://nginx.org/en/CHANGES>`_,
**Angie** adds a number of its own advantages, including these:

- Supporting `HTTP/3
  <https://en.angie.software/angie/docs/configuration/modules/http/http_v3/>`_
  for client connections, as well as for `proxied server
  <https://en.angie.software/angie/docs/configuration/modules/http/http_proxy/#proxy-http-version>`_
  connections, with the ability to independently use different protocol versions
  (HTTP/1.x, HTTP/2, HTTP/3) on opposite sides.

- Automatic HTTPS provisions TLS certificates using built-in `ACME
  <https://en.angie.software/angie/docs/configuration/acme/>`_ support.

- Simplifying configuration: the `location` directive can define several
  matching expressions at once, which enables `combining
  <https://en.angie.software/angie/docs/configuration/modules/http/#combined-locations>`_
  blocks with shared settings.

- Exposing basic information about the web server, its `configuration
  <https://en.angie.software/angie/docs/configuration/modules/http/http_api/#a-api-config-files>`_,
  as well as `metrics
  <https://en.angie.software/angie/docs/configuration/modules/http/http_api/#metrics>`_
  of proxied servers, client connections, shared memory zones, and many other
  things via a RESTful `API
  <https://en.angie.software/angie/docs/configuration/modules/http/http_api/#a-api>`_
  interface in JSON format.

- Exporting statistics in `Prometheus
  <https://en.angie.software/angie/docs/configuration/modules/http/http_prometheus/#prometheus>`_
  format with `customizable templates
  <https://en.angie.software/angie/docs/configuration/modules/http/http_prometheus/#prometheus-template>`_.

- Monitoring the server through the browser with the `Console Light
  <https://en.angie.software/angie/docs/configuration/monitoring/>`_ visual
  monitoring tool.  See the online demo: https://console.angie.software/

- Dynamic updating of upstream groups based on events and labels from `Docker containers
  <https://en.angie.software/angie/docs/configuration/modules/http/http_docker/#http-docker>`_
  (or similar tools like Podman) without server reload.

- Flushing the shared memory zone in `proxy_cache_path
  <https://en.angie.software/angie/docs/configuration/modules/http/http_proxy/#proxy-cache-path>`_
  on disk preserves the cache index contents between restarts and updates,
  which eliminates the cache load delay and brings the server online even
  faster.

- `Session binding
  <https://en.angie.software/angie/docs/configuration/modules/http/http_upstream/#u-sticky>`_
  mode, which directs all requests within one session to the same proxied
  server.

- Recommissioning upstream servers after a failure smoothly using the
  `slow_start` option of the `server
  <https://en.angie.software/angie/docs/configuration/modules/http/http_upstream/#u-server>`_
  directive.

- Limiting the `MP4 file transfer rate
  <https://en.angie.software/angie/docs/configuration/modules/http/http_mp4/#mp4-limit-rate>`_
  proportionally to its bitrate, thus reducing the bandwidth load.

- Extending authorization and balancing capabilities for the MQTT protocol with
  the `mqtt_preread
  <https://en.angie.software/angie/docs/configuration/modules/stream/stream_mqtt_preread/#s-mqtt-preread>`_
  directive under `stream`.

- Informing balancing decisions with RDP protocol's session cookies via the
  `rdp_preread
  <https://en.angie.software/angie/docs/configuration/modules/stream/stream_rdp_preread/#rdp-preread>`_
  directive under `stream`.

- Pre-built `binary packages
  <https://en.angie.software/angie/docs/installation/oss_packages/#install-thirdpartymodules-oss>`_
  for many popular third-party modules.

- `Server
  <https://en.angie.software/angie/docs/configuration/modules/http/http_ssl/#ssl-ntls>`_-
  and `client-side
  <https://en.angie.software/angie/docs/configuration/modules/http/http_proxy/#proxy-ssl-ntls>`_
  support for NTLS when using the `TongSuo
  <https://github.com/Tongsuo-Project/Tongsuo>`_ TLS library, enabled `at build
  time <https://en.angie.software/angie/docs/installation/sourcebuild/#install-source-features>`_.
