.. image:: misc/logo.gif
  :alt: Angie logo
  :target: https://angie.software/en/

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

To start using **Angie**, see the official documentation:

- Installation: https://angie.software/en/installation/

- Runtime configuration: https://angie.software/en/configuration/

- Development and contribution: https://angie.software/en/development/

- Troubleshooting and feedback channels: https://angie.software/en/troubleshooting/


Features
--------

On top of all the capabilities of
`nginx 1.25.4 <https://nginx.org/en/CHANGES>`_,
**Angie** adds a number of its own advantages, including these:

- Supporting `HTTP/3
  <https://angie.software/en/configuration/modules/http_v3/>`_ for client
  connections, as well as for `proxied server
  <https://angie.software/en/configuration/modules/http_proxy/#proxy-http-version>`_
  connections, with the ability to independently use different protocol versions
  (HTTP/1.x, HTTP/2, HTTP/3) on opposite sides.

- Automatic HTTPS provisions TLS certificates using built-in `ACME
  <https://angie.software/en/configuration/modules/http_acme/>`_ support.

- Simplifying configuration: the location directive can define several matching
  expressions at once, which enables `combining
  <https://angie.software/en/configuration/modules/http_core/#combined-locations>`_
  blocks with shared settings.

- Exposing basic information about the web server, its `configuration
  <https://angie.software/en/configuration/modules/http_api/#a-api-config-files>`_,
  as well as `metrics
  <https://angie.software/en/configuration/modules/http_api/#metrics>`_ of
  proxied servers, client connections, shared memory zones, and many other
  things via a RESTful `API
  <https://angie.software/en/configuration/modules/http_api/#a-api>`_ interface
  in JSON format.

- Exporting statistics in `Prometheus
  <https://angie.software/en/configuration/modules/http_prometheus/#prometheus>`_
  format with `customizable templates
  <https://angie.software/en/configuration/modules/http_prometheus/#prometheus-template>`_.

- Monitoring the server through the browser with the `Console Light
  <https://angie.software/en/configuration/monitoring/>`_ visual monitoring
  tool. See the online demo: https://console.angie.software/

- Automatically `updating
  <https://angie.software/en/configuration/modules/http_upstream/#reresolve>`_
  lists of proxied servers matching a domain name or `retrieving
  <https://angie.software/en/configuration/modules/http_upstream/#reresolve>`_
  such lists from SRV DNS records.

- `Session binding
  <https://angie.software/en/configuration/modules/http_upstream/#u-sticky>`_
  mode, which directs all requests within one session to the same proxied
  server.

- Recommissioning upstream servers after a failure smoothly using the slow_start
  option of the `server
  <https://angie.software/en/configuration/modules/http_upstream/#u-server>`_
  directive.

- Limiting the `MP4 file transfer rate
  <https://angie.software/en/configuration/modules/http_mp4/#mp4-limit-rate>`_
  proportionally to its bitrate, thus reducing the bandwidth load.

- Extending authorization and balancing capabilities for the MQTT protocol with
  the `mqtt_preread
  <https://angie.software/en/configuration/modules/stream_mqtt_preread/#s-mqtt-preread>`_
  directive under stream.

- Pre-built `binary packages
  <https://angie.software/en/installation/#install-thirdpartymodules>`_ for many
  popular third-party modules.

- `Server
  <https://angie.software/en/configuration/modules/http_ssl/#ssl-ntls>`_- and
  `client-side
  <https://angie.software/en/configuration/modules/http_proxy/#proxy-ssl-ntls>`_
  support for NTLS when using the `TongSuo
  <https://github.com/Tongsuo-Project/Tongsuo>`_ TLS library, enabled `at build
  time <https://angie.software/en/installation/#building-from-source>`_.
