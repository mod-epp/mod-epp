# mod\_epp

## OVERVIEW

This Apache 2.x module implements the EPP over TCP protocol as defined
in [https://tools.ietf.org/html/rfc5734](RFC5734) and the session
management parts of [https://tools.ietf.org/html/rfc5730](RFC5730).

This is *not* a full implementation of EPP, this module just makes it
possible to write an EPP server as a set of CGI scripts.

The homepage of this software is
[https://github.com/mod-epp/mod-epp](https://github.com/mod-epp/mod-epp)
where you can find the latest version. This is version 1.10, released in
November 2013.

## RATIONALE

EPP is an XML-based protocol, but it does not utilise one of the common
XML based transaction protocols like SOAP, XML-RPC or HTTP. Writing an
EPP server does not only involve programming the registry logic, as all
the server infrastructure (authentication, logging, security,
build-system, portability, etc) cannot be based on a well-established
framework. In our opinion, this is the main reason why there is no open
source implementation of server-side EPP.

Fortunately, the Apache 2.x HTTP server is versatile and flexible enough
to accommodate other protocols than HTTP through the "Module" extension
mechanism. As part of Apache's support for DAV, a basic set of XML
parsing and handling is already included in the Apache framework.

## IMPLEMENTATION

mod\_epp implements an Apache 2.x "connection handler" which reads EPP
frames (as encapsulated according to the EPP/TCP spec), does some
rudimentary XML parsing and converts the data to a normal Apache request
object which can be handled by e.g. a CGI script.

The actual EPP command (as XML text) is passed to the handler encoded as
HTTP form-encoded data, which makes it accessible to normal HTML form
processing environments.

On the output side, mod\_epp installs an "output filter" which will
encapsulate the output of the actual EPP processor (e.g. the CGI-script)
in an EPP/TCP frame.

As of the current version, mod\_epp does not validate incoming
EPP requests according to the EPP XML schema. It only checks
for XML-wellformedness and some rudimentary constraints
on the XML structure in so far as needed to

* generate suitable URLs to call the right scripts
* handle EPP <login> and <logout> commands
* extract authentication information from the request

## INSTALLATION

You should have a recent Apache 2.x, compiled and installed (including
header files!).

Unpack the distribution and run:

    apxs2 -a -c -i mod\_epp.c

The -a should put something like

    LoadModule epp_module         modules/mod\_epp.so

into your httpd.conf file to load the module.

See the man page of `apxs2` (part of the Apache 2.x httpd distribution)
or [http://www.onlamp.com/topics/apache/apache_modules](http://www.onlamp.com/topics/apache/apache_modules)
for further information on compiling and installing Apache modules.

The mod\_epp module does not replace the HTTP functionality
of Apache 2.x, the server can still be used to serve web pages
on a different port.

There has been a change in the Apache internal filter API recently;
this module was developed for 2.0.43. Version 2.0.39 is definitely
too old.

I've tested the module with Apache 2.0.49, and did not detect any errors
any more. If you use an older version, please have a look at:

If you turn on StdEnvVars, you might run into a core dump. Please have a
look at [http://nagoya.apache.org/bugzilla/show_bug.cgi?id=15057](http://nagoya.apache.org/bugzilla/show_bug.cgi?id=15057)
for a possible workaround.

mod\_epp triggers a bug in mod_ssl. See
[http://nagoya.apache.org/bugzilla/show_bug.cgi?id=18339](http://nagoya.apache.org/bugzilla/show_bug.cgi?id=18339)
for more information including a patch.

Success has been reported with Apache 2.0.55. As of version 1.4,
mod\_epp also works with Apache 2.2. Version 1.7 was developed using
Apache 2.2.15. Version 1.9 made mod\_epp compatible with Apache 2.2.22.

(There is one issue, though: Some optimizations within Apache 2.2
don't start the connection handler until the first bytes are received
from the client. That's fine for HTTP, but not EPP. See below.)

As all versions since 1.7 were developed for Apache 2.2.x, support for
Apache 2.0.x might have been broken.

## CONFIGURATION

All configuration is done inside the main Apache config
file "httpd.conf". See also the comments in the example
file which is included in the mod\_epp distribution.

First of all, we need to tell Apache to listen on the EPP port:

    # from: http://www.iana.org/assignments/port-numbers
    # epp             700/tcp    Extensible Provisioning Protocol
    Listen  700

    # for Apache 2.2, we need to be called on connection open, not on
    # "data available", thus:
    AcceptFilter epp none
    Listen 700 epp

To activate mod\_epp for this port we use:

    <VirtualHost *:700>
        EPPEngine On
    </VirtualHost>

Inside the <VirtualHost> context you can specify further
parameters concerning mod\_epp (listed here with the defaults):

    EPPCommandRoot          /epp/command
    EPPSessionRoot          /epp/session
    EPPErrorRoot            /epp/error
    EPPAuthURI              /epp/auth/login

### Detailed description

EPPCommandRoot defines how mod\_epp will build the path to the script
handling any command. If the EPP message contained e.g.
<epp> <command> <foobar/> </command> </epp>
then it will use "$EPPCommandRoot/foobar".

This is URL-Space! If you want to map to static files,
use a path relativ to DocumentRoot. If you want to
point to CGI scripts, you need a "ScriptAlias" directive
to map that URL-space directory to a file-system directory
containing the actual scripts.

EPPSessionRoot defines how mod\_epp will build the path to the script
handling any session handling events. This includes
"hello", "login", and "logout".

EPPErrorRoot is the base path for all error handler calls. These
can be cgi-scripts which can make use of the following parameters:

	code	EPP error code (decimal number)
	clTRID	Client Transaction ID (if available)
	msg	Human readable error message

Currently, mod\_epp will call the following scripts unter
EPPErrorRoot:

	parse		XML parsing error.
	schema		If a violation of the EPP schema is detected.
			(i.e.  mod\_epp cannot make sense of the XML
			tree.)
	protocol	Wrong sequence of EPP frames detected.
			This concerns primarily EPP state-machine
			problems.)
	authrequired	Authentication required, but not supplied.
	internal	mod\_epp internal error.

EPPAuthURI defines the strategy mod\_epp uses to authenticate users.

There are two different approaches:

(1)  EPPAuthURI defines a Path which accessed during the EPP <login>
command. No document is actually retrieved from this location, mod\_epp
just checks if the username/password pair would suffice to access that
location.

You should protect that URI with whatever access control mechanism you want
to apply to the whole setup.

All further requests in this EPP session will inherit this
authentication information.

Example config (within the EPP VirtualHost):

    <Location /epp/auth>
    	AuthType Basic
    	AuthName "EPP"
    	AuthUserFile <some-path>/htpasswd
    	require valid-user
    </Location>

The rationale for this setup is the following: As the
authentication procedure could be expensive, we decided
not to require apache authentication on the normal EPP
commands. By issuing a pseudo-request on login, the
expensive checks can be performed just once for all commands.

mod\_epp will insert a REMOTE_USER header in all subsequent
requests from the same connection even if no apache-side
authentication is done for requests after the initial
login procedure.

In such a setup you have to make sure that the EPP command
scripts are *not* callable via a normal HTTP port.

This use of EPPAuthURI does not work with mod_proxy to a remote
http server.

(2)  If EPPAuthURI is set to "implicit", then no special access
test will be made. Instead, the return code of the actual
<login> Apache request will be checked.

This works with mod_proxy.

EPPReturncodeHeader defines a Header with which the CGI/HTTP backend can
communicate the EPP return code to mod\_epp.

mod\_epp will use this header for:

* If implicit authentication is active, a 1xxx return code
  on <login> counts as successful login, anything else as login failed.

* If the second digit of the return-code is '5' (x5yy), then
  mod\_epp will close the connection to the client.

EPPRawFrame can be used to name a CGI parameter which will contain the
original EPP message.

Older versions of mod\_epp included a EPPVersion command to select
between draft versions of EPP. Now that the RFCs have been published,
I removed this option.

## SSL SUPPORT

EPP can be layered on Apache 2.x mod_ssl. The configuration should look
something like this:

    Listen  700
    <VirtualHost *:700>
        SSLEngine on
        SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL
        SSLCertificateFile /.../server.crt
        SSLCertificateKeyFile /.../server.key

        SSLCACertificateFile /.../cacert.pem
        SSLVerifyClient optional_no_ca

        <Directory "/.../cgi-bin">
        	SSLOptions +StdEnvVars +ExportCertData
        </Directory>

        CustomLog logs/epp_ssl_request_log "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

        EPPEngine On

        [and other EPP directives; see above.]

    </VirtualHost>

Bug Alert: The client CERT does not show up in the first
(fake) hello request.

Bug Alert 2: *older Apache Versions only, 2.0.49 seems to be fine*
If there are any SSL negotiation or configuration problems, the
Apache process might dump core. Please have a look at
[http://nagoya.apache.org/bugzilla/show_bug.cgi?id=18339](http://nagoya.apache.org/bugzilla/show_bug.cgi?id=18339)
where I propose the following patch to Apache 2.0.44:

    --- httpd-2.0.44/modules/ssl/ssl_engine_io.c.old    Mon Jan 13 18:35:22 2003
    +++ httpd-2.0.44/modules/ssl/ssl_engine_io.c        Tue Mar 25 21:07:47 2003
    @@ -997,6 +997,7 @@
    SSL_free(ssl);
    sslconn->ssl = NULL;
    filter_ctx->pssl = NULL; /* so filters know we've been shutdown */
    +    c->aborted = 1;

    return APR_SUCCESS;
    }

## REQUEST/SCRIPT INTERFACE

As explained above, mod\_epp translates EPP commands into HTTP-like
requests, where all parameters and arguments are passed like they are
for HTML FORMs. It is thus possible to use any normal CGI library to
parse the requests and extract the arguments. While it is certainly
possible to handle the requests in various fashions, I will concentrate
on the CGI case here.

The script output must conform to the CGI spec, thus it has to
generate a "Content-Type:" header. Currently, mod\_epp does not
care what you specify there, it will simply pass the body
to the client.

If the script wants to tear down the connection to the client,
it has to include "Connection: close" in the header of the
answer. This convention was selected in analogy to HTTP 1.1.
As the Connection header is a hop-by-hop header and doesn't get
passed over a HTTP proxy, "X-Connection: close" works, too.

mod\_epp generates a random string for each EPP connection and passes
this to the backend as a Cookie with the name "session".
This can be used for session tracking.

### Command Interface:

EPP commands are translated to HTTP POST commands, using
"Content-Type: multipart/form-data" to encapsulate the
arguments. (Exception: the pseudo <hello> request on
connection open is done as HTTP GET with URL-encoded
arguments.) The following two parameters will be passed:

"frame": This contains the XML of the EPP command received
	from the client. This is *not* the original XML text
	as received from the client; it is a serialisation of
	the XML tree built from the client's message. Thus this is
	guaranteed to be valid XML.

**Although mod\_epp does some _very_ basic tests on the XML structure,
mod\_epp does *NOT* do schema verification.**

"clTRID": If mod\_epp succeeds in extracting the "client
	transaction ID" of the request, it will pass it
	along to the scripts as the clTRID parameter.
	(Can be empty.)

The rationale behind this feature is, that if
	the CGI cannot parse the XML due to schema violations
	it still can formulate an error reply tagged
	with the correct clTRID.

The EPPRawFrame parameter can be used to expose the original EPP
message to the backend.

Session commands use the same interface.

### Error Interface:

If mod\_epp detects an error (e.g. invalid XML, failed
login, problems with CGIs), it first tries to call an
external error handler (using a GET request), before
falling back to an internally generated error message.

These error handles receive the following parameters.

"code"		4-digit error code as defined in the RFC
"clTRID"	Client transaction ID (can be empty)
"msg"		Human readable error message

## EXAMPLE SCRIPTS

The directory "examples" contains some static responses as well
as some scripts which generate simple answers to some common EPP
queries. They are *not* useful for a real EPP server, they just
serve as script interface examples.

A sample implementation of a real EPP server is outside the scope of
mod\_epp.

## REVERSE PROXY SETUP

It is possible to run a mod\_epp enabled Apache 2.x as proxy between
the world of EPP and HTTP. This is the ideal setup if your favorite
scripting engine is not supported inside Apache 2.x. For example, you
can proxy to an Apache 1.3.x with PHP or mod_perl, or even to an IIS
running ASP scripts.

Here is an example where access control and error generation
is local, but all command and session scripts are proxied
to a different server:

    Listen  700
    <VirtualHost *:700>
        EPPEngine On

        EPPCommandRoot          /proxy/command
        EPPSessionRoot          /proxy/session
        ProxyPass /proxy/ http://localhost:8000/epp/

        # requests will go to e.g.
        # http://localhost:8000/epp/command/transfer

        EPPErrorRoot            /cgi-bin/epp/error
        EPPAuthURI              /epp/auth/login
        <Location /epp/auth>
           Auth ...
        </Location>
    </VirtualHost>

Authentication information will be passed using an "Authorization:
Basic" header.

Version 1.6 was written to better support this setup.

In order to have the remote backend handle the authentication as well,
use e.g.

    EPPAuthURI              implicit
    EPPReturncodeHeader     X-EPP-Returncode

and on the remote side use the aequivalent of

    <Location /epp/session/login>
       Auth ...
    </Location>

In this case, the remote Apache will do the password checking. You need
to provide a suitable Error-document, as the default HTML on is not
legal EPP.

Alternatively, don't use the webserver itself to check the password, and
return always HTTP 200, but add a X-EPP-Returncode header. e.g.

    Content-Type: text/xml
    X-EPP-Returncode: 2200

mod\_epp will use the first digit to determine whether <login> was
successful or not.

The basic connection close mechanism does not work in this setup. You
can either send a X-Connection: close, or a EPP Return Code header with
the second digit set to '5' to close the connection.

### DEBUGGING HINTS

The code is liberally sprinkled with debugging output. In order to see
what mod\_epp is doing, run apache like this:

    httpd -e debug -X

When using gdb, make sure that you use the .gdbinit file that comes with
the apache 2.x source code and mod\_epp. The "dump\_bucket" and
"dump\_brigade" macros defined in there are *really* helpful.

To build a httpd with debugging symbols, use

    CFLAGS='-g' ./configure --with-included-apr --enable-proxy-http --enable-proxy

in the httpd source tree.

For debugging under Debian use

    export DEB_BUILD_OPTIONS="debug nostrip noopt" dpkg-buildpackage -us -uc

to build the Apache packages. The debugging options might not be picked
up by apxs2, so you might want to use

    "apxs2 -c -i -Wc,-O0 -Wc,-g  mod\_epp.c"

to force this.

AUTHOR
------

This module was developed by Otmar Lendl under contract
from NIC.at. You can reach the author at lendl@nic.at.

Version 1.6 was sponsored by SIDN.
Version 1.7 was sponsored by CentralNic.
Version 1.8 was sponsored by SIDN.
Version 1.9 was sponsored by CentralNic.
Version 1.10 was sponsored by CentralNic.

LICENCE
-------

	/*
	* Copyright (c) 2002 NIC.at Internet Verwaltungs- und
	* Betriebsgesellschaft m. b. H. All rights reserved.
	*
	* Written by Otmar Lendl <lendl@nic.at>
	*
	* Redistribution and use in source and binary forms, with or without
	* modification, are permitted provided that the following conditions
	* are met:
	*
	* 1. Redistributions of source code must retain the above copyright
	*    notice, this list of conditions and the following disclaimer.
	*
	* 2. Redistributions in binary form must reproduce the above copyright
	*    notice, this list of conditions and the following disclaimer in
	*    the documentation and/or other materials provided with the
	*    distribution.
	*
	* 3. The end-user documentation included with the redistribution,
	*    if any, must include the following acknowledgment:
	*        "This product includes software developed by the
	*        NIC.at Internet Verwaltungs- und Betriebsgesellschaft m. b. H."
	*    Alternately, this acknowledgment may appear in the software itself,
	*    if and wherever such third-party acknowledgments normally appear.
	*
	* 4. The names "mod\_epp" and "NIC.at" must
	*    not be used to endorse or promote products derived from this
	*    software without prior written permission. For written
	*    permission, please contact lendl@nic.at
	*
	* 5. Products derived from this software may not be called "mod\_epp",
	*    nor may "mod\_epp" appear in their name, without prior written
	*    permission of NIC.at.
	*
	* THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
	* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
	* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	* DISCLAIMED.  IN NO EVENT SHALL NIC.AT INTERNET VERWALTUNGS- UND
	* BETRIEBSGESELLSCHAFT M.B.H. OR
	* ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
	* USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
	* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
	* OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
	* SUCH DAMAGE.
	*
	*/