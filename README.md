# ngx_http_security_headers_filter_module

This NGINX module adds security headers. 

## Synopsis

```nginx
http {
    security_headers on;
    hsts on;
    ...
}
```

Running `curl -IL https://example.com/` will yield the added security headers:

<pre>
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 21 May 2019 16:15:46 GMT
Content-Type: text/html; charset=UTF-8
Vary: Accept-Encoding
Accept-Ranges: bytes
Connection: keep-alive
<b>X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Referrer-Policy: same-origin
Strict-Transport-Security: max-age=31536000</b>
</pre>

In general, the module features sending security HTTP headers in a way that better conforms to the standards.
For instance, `Strict-Transport-Security` header should *not* be sent for plain HTTP requests.
The module follows this recommendation.

## Key Features

*   Plug-n-Play: the default set of security headers can be enabled with `security_headers on;` in your NGINX configuration
*   The module does not send `Strinct-Transport-Security` via `security_headers` directive. You must enable it by setting the `hsts` directive to on.
*   Sends HTML-only security headers for relevant types only, not sending for others, e.g. `X-Frame-Options` is useless for CSS
*   Plays well with conditional `GET` requests: the security headers are not included there unnecessarily
*   Does not suffer the `add_header` directive's pitfalls
*   Hides `X-Powered-By` and other headers which often leak software version information
*   Hides `Server` header altogether, not just the version information

## Configuration directives

### `security_headers`

- **syntax**: `security_headers on | off;`
- **default**: `security_headers off;`
- **context**: `http`, `server`, `location`, `when`

Enables or disables applying security headers (`Strict-Transport-Security` is not included). The default set includes:

* `X-Frame-Options: SAMEORIGIN`
* `X-XSS-Protection: 0`
* `Referrer-Policy: sameorigin`
* `X-Content-Type-Options: nosniff`

The values of these headers (or their inclusion) can be controlled with other `security_headers_*` directives below.

### `security_headers_x_xss_protection`

- **syntax**: `security_headers_x_xss_protection off | on | block | clear | bypass;`
- **default**: `security_headers_x_xss_protection off;`
- **context**: `http`, `server`, `location`, `when`

Controls `X-XSS-Protection` header. 
The `off` value is for disabling XSS protection: `X-XSS-Protection: 0`.
This is the default because 
[modern browsers do not support it](https://github.com/GetPageSpeed/ngx_security_headers/issues/19) and where it is 
supported, it introduces vulnerabilities.
The `on` value is for enabling XSS protection: `X-XSS-Protection: 1;`.
The `block` value is for blocking XSS attacks: `X-XSS-Protection: 1; mode=block`.
The `clear` value is for clearing the header.
The `bypass` value is for disabling adding or rewriting the header by the module.

### `security_headers_x_frame_options`

- **syntax**: `security_headers_x_frame_options sameorigin | deny | clear | bypass;`
- **default**: `security_headers_x_frame_options sameorigin;`
- **context**: `http`, `server`, `location`, `when`

Controls inclusion and value of `X-Frame-Options` header. 
Special `bypass` value will disable adding or rewriting the header by the module.


### `security_headers_referrer_policy`

- **syntax**: `security_headers_referrer_policy strict-origin-when-cross-origin | no-referrer | no-referrer-when-downgrade | origin | origin-when-cross-origin | same-origin | strict-origin | unsafe-url | clear | bypass;`
- **default**: `security_headers_referrer_policy strict-origin-when-cross-origin;`
- **context**: `http`, `server`, `location`, `when`

Controls inclusion and value of [`Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) header. 
Special `clear` value will clear the header.
Special `bypass` value will disable adding or rewriting the header by the module.

### `security_headers_x_content_type_options`

- **syntax**: `security_headers_x_content_type_options nosniff | clear | bypass;`
- **default**: `security_headers_x_content_type_options nosniff;`
- **context**: `http`, `server`, `location`, `when`

Controls inclusion and value of `X-Content-Type-Options` header.
Special `clear` value will clear the header.
Special `bypass` value will disable adding or rewriting the header by the module.

### `security_headers_types`

- **syntax**: `security_headers_types mime-type ...;`
- **default**: `security_headers_types text/html application/xhtml+xml text/xml text/plain;`
- **context**: `http`, `server`, `location`

Controls which mine types need to send security headers. But the `Strict-Transport-Security` header is an exception. `Strict-Transport-Security` is valid for all files.

### `hsts`

- **syntax**: `hsts on | bypass | clear;`
- **default**: `hsts bypass;`
- **context**: `http`, `server`, `location`, `when`

Controls `Strict-Transport-Security` header. This directive takes effect independently and is not controlled by the `security_headers` directive.
The `on` value is for enabling `Strict-Transport-Security` header.
Special `clear` value will clear the header.
Special `bypass` value will disable adding or rewriting the header by the module.


### `hsts_max_age`

- **syntax**: `hsts_max_age time;`
- **default**: `hsts_max_age 31536000s;`
- **context**: `http`, `server`, `location`, `when`

Sets the value of the `max-age` parameter in the `Strict-Transport-Security` header.


### `hsts_includesubdomains`

- **syntax**: `hsts_includesubdomains on | off;`
- **default**: `hsts_includesubdomains off;`
- **context**: `http`, `server`, `location`, `when`

Enable or disable the `includeSubDomains` parameter in the `Strict-Transport-Security` header.


### `hsts_preload`

- **syntax**: `hsts_preload on | off;`
- **default**: `hsts_preload off;`
- **context**: `http`, `server`, `location`, `when`

Enable or disable the `preload` parameter in the `Strict-Transport-Security` header.
This means Chrome may and will include your websites to its preload list of domains which are HTTPS only.
It is usually what you want anyway, but bear in mind that in some edge cases you want to access a subdomain via plan unencrypted connection.
If you absolutely sure that all your domains and subdomains used with the module will ever primarily operate on HTTPs, proceed without any extra step.

## Install

We highly recommend installing using packages, where available,
instead of compiling.

### CentOS/RHEL, Amazon Linux and Fedora packages

It's easy to install the module package for these operating systems.

`ngx_security headers` is part of the NGINX Extras collection, so you can install
it alongside [any modules](https://nginx-extras.getpagespeed.com/), 
including PageSpeed and Brotli.

```bash
sudo yum -y install https://extras.getpagespeed.com/release-latest.rpm
sudo yum -y install nginx-module-security-headers
```


Then add it at the top of your `nginx.conf`:

```nginx
load_module modules/ngx_http_security_headers_filter_module.so;
```
    
In case you use ModSecurity NGINX module, make sure it's loaded last, like so:

```nginx
load_module modules/ngx_http_security_headers_filter_module.so;
load_module modules/ngx_http_modsecurity_module.so;
```

### Other platforms

Compiling NGINX modules is [prone to many problems](https://www.getpagespeed.com/server-setup/where-compilation-went-wrong), 
including making your website insecure. Be sure to keep your NGINX and modules updated, if you go that route.

To compile the module into NGINX, run:

```bash
./configure --with-compat --add-module=../ngx_security_headers
make 
make install
```

Or you can compile it as dynamic module. In that case, use `--add-dynamic-module` instead, and load the module after 
compilation by adding to `nginx.conf`:

```nginx
load_module /path/to/ngx_http_security_headers_filter_module.so;
```
