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
 * 4. The names "mod_epp" and "NIC.at" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact lendl@nic.at
 *
 * 5. Products derived from this software may not be called "mod_epp",
 *    nor may "mod_epp" appear in their name, without prior written
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

#include "httpd.h"
#define CORE_PRIVATE
#include "http_protocol.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_buckets.h"
#include "apr_xml.h"
#include "apr_general.h"
#include "util_filter.h"
#include "scoreboard.h"
#include "apr_md5.h"

#include "mod_epp.h"

#include <sys/types.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>



module AP_MODULE_DECLARE_DATA epp_module;


/*
 * table debugging helpers
 */

int epp_dump_table_entry(void *rec, const char *key, const char *value) {

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		(char *)rec, key, value);
	return(1);
}

void epp_dump_table(apr_table_t *t, const char *s) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"%s: Dumping table %lx", s, (long) t);
	apr_table_do(&epp_dump_table_entry,(void *) "DUMP: %s: %s\n", t, NULL);
}


/*
 * Generate the session identifying cookie
 *
 * It's a MD5 hash over
 * 	the connection struct
 *	current time
 *	process id + parent id
 *
 * (we don't need unpredictability, just uniqueness)
 *
 */
void epp_make_cookie(epp_user_rec *ur)
{
apr_md5_ctx_t md5ctx;
unsigned char hash[APR_MD5_DIGESTSIZE];
const char *hex = "0123456789abcdef";
char *r; 
int i;
time_t t;
pid_t pids[2];

time(&t);

pids[0] = getpid();
pids[1] = getppid();

apr_md5_init(&md5ctx);
apr_md5_update(&md5ctx, (void *)ur->c, sizeof(conn_rec));
apr_md5_update(&md5ctx, (void *)&t, sizeof(t));
apr_md5_update(&md5ctx, (void *)pids, sizeof(pids));
apr_md5_final(hash, &md5ctx);

r = apr_cpystrn(ur->cookie, "session=", 9);
for (i = 0; i < APR_MD5_DIGESTSIZE; i++) 
	{
	*r++ = hex[hash[i] >> 4];
	*r++ = hex[hash[i] & 0xF];
	}
*r = '\0';
}

/* two simple xml helpers from mod_jabber */

char *get_attr(apr_xml_attr *attr, const char *name) 
{
if (attr == NULL) return NULL;
if (!strcmp(attr->name,name)) return (char *)attr->value;
return get_attr(attr->next, name);
}

apr_xml_elem *get_elem(apr_xml_elem *elem, const char *name) 
{
if (elem == NULL) return NULL;
if (!strcmp(elem->name,name)) return elem;
return get_elem(elem->next, name);
}


/*
 * actually, this is probably overkill, we parsed the XML in
 * one swoop and thus don't expect fragmented cdata.
 */
void xml_firstcdata_strncat(char *dest, size_t dstsize, apr_xml_elem *elem)
{
apr_text *t;

dstsize--;
dest[dstsize] = 0;
dest[0] = 0;

for (t = elem->first_cdata.first; t; t = t->next) 
	{
	strncat(dest, t->text, dstsize);
	dstsize -= strlen(t->text);
	if (dstsize < 1) break;
	}
}


static request_rec *epp_create_request(epp_user_rec *ur)
{
apr_pool_t *p;
request_rec *r;

apr_pool_create(&p, ur->pool);
apr_pool_tag(p, "mod_epp_request");	/* helps debugging */

r                  = apr_pcalloc(p, sizeof(*r));
r->pool            = p;
r->connection      = ur->c;
r->server          = ur->c->base_server;

ur->c->keepalive   = 0;

r->user            = NULL;
r->ap_auth_type    = NULL;

r->allowed_methods = ap_make_method_list(p, 2);

r->headers_in      = apr_table_make(r->pool, 10);
r->subprocess_env  = apr_table_make(r->pool, 10); /* will need this */
r->headers_out     = apr_table_make(r->pool, 1);
r->err_headers_out = apr_table_make(r->pool, 1);
r->notes           = apr_table_make(r->pool, 5);

r->request_config  = ap_create_request_config(r->pool);
ap_run_create_request(r);
r->per_dir_config  = r->server->lookup_defaults;

r->sent_bodyct     = 1;
r->bytes_sent	   = 0;

r->output_filters  = ur->c->output_filters;
r->input_filters   = ur->c->input_filters;

r->status = HTTP_OK;                         /* Until further notice. */
r->request_time	   = apr_time_now();

ap_set_module_config(r->request_config, &epp_module, ur);

apr_table_set(r->headers_in, "User-Agent", EPP_USER_AGENT);

return r;
}

/*
 * Take an epp request struct and try to find the clTRID.
 *
 */
apr_status_t epp_get_cltrid(epp_rec *er)
{
apr_xml_elem *id,*root,*e;

/* default to no cltrid */
er->cltrid[0] = 0;

root = er->doc->root;

if(strcmp("epp",root->name))
	return(APR_BADARG);

/*
 * got to first level below root.
 */
e = root->first_child;
if (e == NULL)
	return(APR_BADARG);

/*
 * there should be exactly one element below <epp> ...
 */
if (e->next != NULL)
	return(APR_BADARG);

/*
 * ... and it should not be "clTRID".
 */
if(!strcmp("clTRID",e->name))
	return(APR_BADARG);


id = get_elem(e->first_child, "clTRID");
if (id == NULL)
	{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"EPP: did not find a clTRID.");
	return(APR_SUCCESS);
	}


xml_firstcdata_strncat(er->cltrid, sizeof(er->cltrid), id);

ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
	"EPP: found clTRID = %s.", er->cltrid);

return(APR_SUCCESS);
}


/*
 * Take an XML tree and build a URI path from the commands found
 *
 * TODO: actually, the tree should have been validated by now, but as
 * we don't do XML schema checks right now, we go for *really* simple checks.
 *
 * This function returns 
 * 	APR_SUCCESS	just call it
 * 	APR_BADARG	schema error
 * 	
 *
 * The URI will be returned in "path". It will be either based
 * on EPPSessionRoot or EPPCommandRoot.
 *
 * "element" will point to the relevant node in the XML tree.
 *
 * "login_needed" will be true if the client has to be logged in
 * in order to access this URI. 
 *
 */

apr_status_t epp_translate_xml_to_uri(apr_xml_doc *doc, epp_rec *er, 
		char *path, apr_size_t path_size, apr_xml_elem **element, int *login_needed)
{
apr_xml_elem *command, *c, *hello;
epp_conn_rec *conf = er->ur->conf;

/*
 * default to a schema error and no login needed.
 */
apr_snprintf(path, path_size, "%s/schema", conf->error_root);
*login_needed = 0;

if(strcmp("epp",doc->root->name))
	return(APR_BADARG);

/*
 * Check for a hello frame
 */
hello = get_elem(doc->root->first_child, "hello");
if (hello != NULL)
	{
	apr_snprintf(path, path_size, "%s/hello", conf->session_root);
	if (element)
		*element = hello;
	return(APR_SUCCESS);
	}


/*
 * Not hello? Then it must be a <command>
 */

command = get_elem(doc->root->first_child, "command");
if (command == NULL)
	return(APR_BADARG);


c = command->first_child;
while (c != NULL)
	{
	/*
	 * These two tags are not relevant in the search for the command.
	 */
	if ((!strcasecmp(c->name, "clTRID")) || 
	    (!strcasecmp(c->name, "extension"))) 
		{
		c = c->next;
		continue;
		}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"XML: found command = %s.", c->name);

	if (element)
		*element = c;

	if (!strcmp("login",c->name) || !strcmp("logout",c->name))
		apr_snprintf(path, path_size, "%s/%s", conf->session_root, c->name);
	  else
		apr_snprintf(path, path_size, "%s/%s", conf->command_root, c->name);
	
	if (strcmp("login",c->name))
	 	*login_needed = 1;

	return(APR_SUCCESS);
	}

return(APR_BADARG);
}

/*
 * Check for connection close signalling
 *
 */
void handle_close_request(epp_rec *er, request_rec *r)
{
const char *epp_rc;
const char *connection;
epp_conn_rec *conf = er->ur->conf;

/*
 * Check for the EPP Return Code header
 */
epp_rc = apr_table_get(r->err_headers_out, conf->rc_header);
if (!epp_rc) 
	epp_rc = apr_table_get(r->headers_out, conf->rc_header);

/*
 * Scripts can signal with "Connection: close" that they want to tear down
 * the epp session.
 *
 * This does not work if mod_proxy is used. In this case, the remote
 * script should set "X-Connection: close". For added confusion, in 
 * this case, the header appears in headers_out and not err_headers_out.
 * 
 */
connection = apr_table_get(r->err_headers_out, "Connection");
if (!connection) 
	connection = apr_table_get(r->headers_out, "X-Connection");

/*
 * Alternatively, if they send the EPP return code in a header, use that.
 */
if (connection && !strncmp(connection, "close", 5))
	{
	er->ur->connection_close = 1;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"CGI requested a connection close via Connection-header");
	return;
	}

if (epp_rc && (epp_rc[1] == '5'))	/* x5yy means connection close */
	{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"Connection close based on EPP code %s", epp_rc);
	er->ur->connection_close = 1;
	}
}



/*
 * Call an error handler.
 *
 * Parameters:
 *
 * 		script		name under EPPErrorRoot
 * 		code		EPP error code
 * 		cltrid		Client transaction ID
 * 		errmsg		Human readable error message
 *
 * A simple hardcoded message is sent if the full request doesn't work.
 *
 */
apr_status_t epp_error_handler(epp_rec *er, char *script, int code, char *cltrid, char *errmsg)
{
request_rec *r;
char req[400];
char *e, *id;
char id_xml[100] = "";
epp_conn_rec *conf = er->ur->conf;


r = epp_create_request(er->ur);
er->r = r;

/*
 * html escaping is close enough to XML escaping.
 */
e 	= (errmsg) ? ap_escape_uri(r->pool, errmsg) : "";
id 	= (cltrid) ? ap_escape_uri(r->pool, cltrid) : "";
if(cltrid) 
	apr_snprintf(id_xml, sizeof(id_xml), "<clTRID>%s</clTRID>", id);

apr_snprintf(req, sizeof(req), "%s/%s?code=%d&clTRID=%s&msg=%s", conf->error_root, 
			script, code, id, e);
ap_parse_uri(r, req);

r->assbackwards    = 0;		/* I don't want headers. */
r->method          = "GET";
r->method_number   = M_GET;
r->protocol        = "INCLUDED";
r->the_request     = req;

apr_table_set(r->headers_in, "Cookie", er->ur->cookie);
ap_add_input_filter("EOS_INPUT", (void *) er, r, r->connection);
ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);
ap_process_request(r);
if (ap_extended_status)
	ap_increment_counts(r->connection->sbh, r);



if (r->status != HTTP_OK)	/* something wrong with the script runtime? Go for simple version. */
	{
	ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS , NULL,
		"epp_error_handler: calling %s failed.", req);

	r->status = HTTP_OK;	/* tell the output filter that this error 
				   should be framed and not discarded */

	apr_snprintf(req, sizeof(req), "%s\n<response><result code=\"%d\"><msg>%s</msg>\n</result><trID>%s</trID></response></epp>", 
			EPP_BUILTIN_ERROR_HEAD,
			code, e, id_xml);
	ap_fputs(er->ur->c->output_filters, er->bb_out, req);
    	APR_BRIGADE_INSERT_TAIL(er->bb_out, apr_bucket_eos_create(r->connection->bucket_alloc));
	ap_fflush(er->ur->c->output_filters, er->bb_out);
	}

/*
 * Did the error handle request the connection to be closed?
 */
handle_close_request(er, r);
apr_pool_destroy(r->pool);
return(APR_SUCCESS);
}

/*
 * This function implements the EPP login procedure.
 *
 * It does not generate the answer to the client, that is left 
 * to a "normal" handler. Here we just check the password
 * and set the internal state.
 *
 */
apr_status_t epp_login(epp_rec *er, apr_xml_elem *login)
{
apr_xml_elem *clid_el, *pw_el;

epp_conn_rec *conf = er->ur->conf;
char clid[CLIDSIZE];
char pw[PWSIZE];
char *passwd;
request_rec *r;
apr_status_t res;

ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS , NULL,
	"epp_login: entering");

if (er->ur->authenticated)
	{
	epp_error_handler(er, "login", 2002, er->cltrid, "Already logged in. Use <logout> first.");
	return EPP_PROT_ERROR;
	}
		
clid_el = get_elem(login->first_child, "clID");
pw_el = get_elem(login->first_child, "pw");

if ((clid_el == NULL) || (pw_el == NULL))
	{
	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS , NULL,
		"epp_login: clid or pw missing");
	
	epp_error_handler(er, "schema", 2001, NULL, 
			"Error in login (clID and pw must be present).");
	return(EPP_PROT_ERROR);
	}



xml_firstcdata_strncat(clid, sizeof(clid), clid_el);
xml_firstcdata_strncat(pw, sizeof(pw), pw_el);

ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS , NULL,
	"epp_login: clid = %s, pw = %s", clid, pw);

passwd = apr_psprintf(er->pool, "%s:%s", clid, pw);
er->ur->auth_string = apr_psprintf(er->ur->pool, "Basic %s", ap_pbase64encode(er->ur->pool, passwd));

if (conf->implicit_login)      /* implicit login, no need to do a request here */
	{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS , NULL,
		"epp_login: implicit_login set, no request done");

	apr_cpystrn(er->ur->clid, clid, sizeof(er->ur->clid));
	apr_cpystrn(er->ur->pw, pw, sizeof(er->ur->pw));
	return(APR_SUCCESS);
	}

r = epp_create_request(er->ur);
er->r = r;
apr_table_set(r->headers_in, "Authorization", er->ur->auth_string);
apr_table_set(r->headers_in, "Cookie", er->ur->cookie);

r->the_request	= (char *) er->ur->conf->authuri;
ap_parse_uri(r, (char *) er->ur->conf->authuri);
r->assbackwards    = 0;         /* I don't want headers. */ 
r->method          = "GET";
r->method_number   = M_GET;
r->protocol        = "INCLUDED";


apr_table_set(r->headers_in, "Cookie", er->ur->cookie);
/*
 * ap_process_request_internal does all the auth checks, but does not
 * actually call the handler. Just what we want.
 */
if ((res = ap_process_request_internal(r)) == OK) 
	{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS , NULL,
		"epp_login (success): after ap_process_request_internal: res = %d", res);

	er->ur->authenticated = 1;
	apr_cpystrn(er->ur->clid, clid, sizeof(er->ur->clid));
	apr_cpystrn(er->ur->pw, pw, sizeof(er->ur->pw));
	apr_pool_destroy(r->pool);
	return(APR_SUCCESS);
	}
else
	{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS , NULL,
		"epp_login (fail): after ap_process_request_internal: res = %d", res);

	er->ur->authenticated = 0;
	apr_pool_destroy(r->pool);

	epp_error_handler(er, "login", 2200, er->cltrid, "Username/Password invalid.");
	return(APR_BADARG);
	}
/* not reached */
}

/* 
 * more or less a dummy for now
 */
apr_status_t epp_logout(epp_rec *er, apr_xml_elem *login)
{
er->ur->authenticated	= 0;
er->ur->clid[0]		= 0;
er->ur->pw[0] 		= 0;
er->ur->auth_string[0]	= 0;
return(APR_SUCCESS);
}

/*
 * This is the core function. 
 *
 * We have to a full EPP frame, now build the XML object,
 * do some rudimentary checking, build an URI, an request
 * object and call it.
 *
 */
void epp_process_frame(epp_rec *er)
{
epp_conn_rec *conf = er->ur->conf;
apr_xml_parser *xml_p;
apr_xml_doc *doc;
apr_xml_elem *tag = NULL;
int login_needed;
int is_login = 0;
apr_status_t rv;
char errstr[300];
request_rec *r;
const char *epp_rc;

char uri[200];
char content_length[20];

xml_p = apr_xml_parser_create(er->pool);
rv = apr_xml_parser_feed(xml_p, er->orig_xml, er->orig_xml_size);
apr_xml_parser_geterror(xml_p, errstr, sizeof(errstr));
ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
	"XML parser feed reports: %s", errstr);

rv = apr_xml_parser_done(xml_p,&doc);
apr_xml_parser_geterror(xml_p, errstr, sizeof(errstr));
ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
	"XML parser done reports: %s", errstr);


if (rv != APR_SUCCESS)
	{
	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, NULL,
		"not valid XML");
	epp_error_handler(er, "parse", 2001, NULL, errstr);
	return;
	}

er->doc = doc;

rv = epp_get_cltrid(er);
if (rv != APR_SUCCESS)
	{
	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, NULL,
		"Schema error while looking for clTRID");
	epp_error_handler(er, "schema", 2001, NULL, "Detected a schema error while looking for clTRID");
	return;
	}


rv = epp_translate_xml_to_uri(doc, er, uri, sizeof(uri), &tag, &login_needed);

ap_log_error(APLOG_MARK, ((rv == APR_SUCCESS) ? APLOG_DEBUG : APLOG_WARNING),
		APR_SUCCESS, NULL, "Translated EPP to %s", uri);

/*
 * If translation failed, we already have the error URI here, thus we continue.
 */

if (tag && !strcmp("login",tag->name))	 /* <login> ? */
	{
	is_login = 1;
	rv = epp_login(er, tag);
	if (rv != APR_SUCCESS)
		{
		return;
		}
	}

if (!er->ur->authenticated && login_needed)	/* need login before continuing ? */
	{
	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, NULL,
		"I can't call %s without prior login.", uri);
	epp_error_handler(er, "authrequired", 2002, er->cltrid, "You need to login first.");
	return;
	}

/*
 * now do the actual work
 */

r = epp_create_request(er->ur);
er->r = r;

apr_xml_quote_elem(r->pool,doc->root); /* hat tip Elias Sidenbladh */
apr_xml_to_text(r->pool,doc->root,APR_XML_X2T_FULL_NS_LANG, doc->namespaces ,NULL, &er->serialised_xml, 
			&er->serialised_xml_size);

/*
 * There seems to be a bug somewhere in the size calculations. 
 * If I use the returned serialised_xml_size, I get trailing garbage every now and then.
 * *shrug*, the let's go for strlen, as I hope that there are no null bytes in the XML.
 */
er->serialised_xml_size = strlen(er->serialised_xml);
ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
	"XML: serialized xml size = %lu.", (unsigned long) er->serialised_xml_size);
sprintf(content_length, "%lu", strlen(EPP_CONTENT_FRAME_CGI) 
			+ strlen(EPP_CONTENT_CLTRID_CGI) 
			+ strlen(er->cltrid) 
			+ strlen(EPP_CONTENT_POSTFIX_CGI)
			+ er->serialised_xml_size
			+ ((conf->raw_frame) ? (
				strlen(conf->raw_frame)
				+ er->orig_xml_size) : 0));
	
apr_table_set(r->headers_in, "Content-Type", "multipart/form-data; boundary=--BOUNDARY--");
apr_table_set(r->headers_in, "Content-Length", content_length);
apr_table_set(r->headers_in, "Cookie", er->ur->cookie);

ap_add_input_filter("XMLCGI_INPUT", (void *) er, r, r->connection);

r->assbackwards    = 0;         /* I don't want headers. */
r->method          = "POST";
r->method_number   = M_POST;
r->protocol        = "INCLUDED";
ap_parse_uri(r, uri);		/* also sets the unparsed_uri field */
r->the_request     = uri;       /* make sure the logging is correct */


/*
 * Fake Basic Auth if authenticated or the backend does user/pass checking.
 */
if (er->ur->authenticated || conf->implicit_login )
	{
	apr_table_set(r->headers_in, "Authorization", er->ur->auth_string);
	/*
	 * If the actual command or session URIs are not protected, no
	 * REMOTE_USER CGI environment variable will be produced. Thus we 
	 * fake it here.
	 */
	r->user            = er->ur->clid;
	}

ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);
ap_process_request(r);
if (ap_extended_status)
	ap_increment_counts(r->connection->sbh, r);

ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
	"request status = %d", r->status);

/* debugging stub */
#if 0
epp_dump_table(r->headers_in,"headers_in, after call");
epp_dump_table(r->headers_out,"headers_out, after call");
epp_dump_table(r->err_headers_out,"err_headers_out, after call");
#endif

/*
 * Check for the EPP Return Code header
 */
epp_rc = apr_table_get(r->err_headers_out, conf->rc_header);
if (!epp_rc) 
	epp_rc = apr_table_get(r->headers_out, conf->rc_header);

if (tag && !strcmp("logout",tag->name))
	{
	rv = epp_logout(er, tag);
	}

/*
 * was this a <login>?
 */
if (is_login && conf->implicit_login)	/* did we try to login with this request */
	{
/* 
 * The logic here is a bit tricky: if we get a http 401, login failed.
 * If HTTP_OK, then check for a epp return-code header and analyze it.
 * If no header is found, treat the login as succeeded.
 */
	if (r->status == HTTP_UNAUTHORIZED)
		{
		ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, NULL,
			"epp login failed for %s, error code is %d", er->ur->clid, r->status);
		er->ur->authenticated = 0;
		}
	else if (r->status == HTTP_OK) 
		{
		if (epp_rc) 
		    {
		    if (epp_rc[0] == '1')	/* 1xxx is success */
			{
			ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, NULL,
				"epp login for %s succeeded based on EPP code %s", er->ur->clid, epp_rc);
			er->ur->authenticated = 1;
			}
		    else 
			{
			ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, NULL,
				"epp login for %s failed based on EPP code %s", er->ur->clid, epp_rc);
			er->ur->authenticated = 0;
			}
		    }
		else 
		   {
		   ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, NULL,
			"epp login succeeded for %s based on HTTP code %d", er->ur->clid, r->status);
			er->ur->authenticated = 1;
		   }
		}
	}

/*
 * Troubles executing the request
 */
if ((r->status != HTTP_OK) && (r->status != HTTP_UNAUTHORIZED))
	{
	ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, NULL,
		"Could not execute %s", uri);
	epp_error_handler(er, "internal", 2400, NULL, "Internal error.");
	}

/*
 * Did the backend request the connection to be closed?
 */
handle_close_request(er, r);

apr_pool_destroy(r->pool);
}



/*
 * This implements the pseudo-hello request (connection open).
 *
 * We can't recycle epp_process_frame, as this has to be
 * a GET request to allow SSL renegotiation.
 *
 * See the comments in ssl_engine_kernel.c concerning SSL and POST.
 *
 */
apr_status_t epp_do_hello(epp_rec *er)
{
request_rec *r;
epp_conn_rec *conf = er->ur->conf;

char uri[200];

apr_snprintf(uri, sizeof(uri), "%s/hello?frame=%s", conf->session_root, EPP_BUILTIN_HELLO);
r = epp_create_request(er->ur);
er->r = r;
ap_parse_uri(r, uri);

r->assbackwards    = 0;		/* I don't want headers. */
r->method          = "GET";
r->method_number   = M_GET;
r->protocol        = "INCLUDED";
r->the_request     = uri;	/* make sure the logging is correct */

apr_table_set(r->headers_in, "Cookie", er->ur->cookie);

ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);
ap_add_input_filter("EOS_INPUT", (void *) er, r, r->connection); 
ap_process_request(r);
if (ap_extended_status)
	ap_increment_counts(r->connection->sbh, r);

if (r->connection->aborted)	/* probably a SSL error. */
	{
	return(r->status);
	}

if (r->status != HTTP_OK)	/* something wrong with the script runtime */
	{
	epp_error_handler(er, "internal", 2400, NULL, "Internal error producing greeting.");
	}

apr_pool_destroy(r->pool);
return(APR_SUCCESS);
}


/*
 * Try to implement an aequivalent to the read() system call. 
 * 
 * This read the specified number of bytes from the connection
 * and stores them in the buffer provided.
 *
 * Partial reads are considered as errors. APR_SUCCESS is only
 * returned on reading exactly count bytes.
 *
 */
apr_status_t epp_read(conn_rec *c, apr_pool_t *p, char *buf, apr_size_t count)
{
apr_bucket_brigade *bb;
apr_status_t status;
apr_size_t need_bytes = count;
apr_size_t size;

bb = apr_brigade_create(p, c->bucket_alloc);

while(need_bytes > 0)
	{
	status = ap_get_brigade(c->input_filters, bb, AP_MODE_READBYTES,
		APR_BLOCK_READ, need_bytes);
	if (status != APR_SUCCESS) 
		{
		apr_brigade_destroy(bb);
		return status;
		}

	size = need_bytes;

	status = apr_brigade_flatten(bb, buf, &size);
	if (status != APR_SUCCESS) 
		{
		apr_brigade_destroy(bb);
		return status;
		}

	need_bytes -= size;
	buf += size;

	apr_brigade_cleanup(bb);
	}

apr_brigade_destroy(bb);

return APR_SUCCESS;
}

/*
 *
 * This is the main conncetion handler.
 *
 * It first fires off the greeting, then loops over all incoming
 * EPP requests.
 *
 */
static int epp_process_connection(conn_rec *c)
{
    server_rec *s = c->base_server;
    epp_user_rec *ur;
    epp_rec *er;
    unsigned long framelen, framelen_n;
    apr_pool_t *p, *p_er;
    apr_bucket_brigade *bb_tmp;
    apr_bucket_brigade *bb_out;
    apr_status_t rv;

    char *xml;

    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);

/*
 * If EPP isn't turned on, then we decline here and thus fall back to HTTP.
 */
    if (!conf->epp_on) {
        return DECLINED;
    }

    ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);

    apr_pool_create(&p, c->pool);
    apr_pool_tag(p, "epp_UR_pool");
    ur 		= apr_palloc(p, sizeof(*ur));
    ur->pool 	= p;
    ur->c 	= c;
    ur->authenticated 	= 0;
    ur->failed_logins 	= 0;
    ur->connection_close= 0;
    ur->conf	= conf;
    ur->er	= NULL;

    epp_make_cookie(ur);

    ap_add_output_filter("EPPTCP_OUTPUT", (void *) ur, NULL, c); 

    /* create the brigades */

    bb_tmp = apr_brigade_create(ur->pool, c->bucket_alloc);
    bb_out = apr_brigade_create(ur->pool, c->bucket_alloc);


    /* send greeting */
    apr_pool_create(&p_er, ur->pool); 
    er = apr_palloc(p_er, sizeof(*er));
    er->pool = p_er;
    er->ur = ur;
    ur->er = er;
    er->r = NULL;	/* so that the output filter knows there is no request yet */
    er->bb_out = bb_out;
    er->bb_tmp = bb_tmp;
    rv = epp_do_hello(er);

    if (rv != APR_SUCCESS)		/* this could be a SSL negotiation error */
    {					/* or not. something is fishy here */
	ap_log_error(APLOG_MARK, APLOG_ERR, rv , NULL,
		"Aborting connection (probably a SSL negotiation error).");
	APR_BRIGADE_INSERT_TAIL(bb_out, apr_bucket_eos_create(c->bucket_alloc));
	ap_pass_brigade(c->output_filters, bb_out);
	
	apr_pool_destroy(p);		/* not really needed */
	return OK;			/* bail out */
    }

    apr_pool_destroy(p_er);

    /* loop over all epp frames */
    for ( ; ; )
	{
	ap_update_child_status(c->sbh, SERVER_BUSY_KEEPALIVE, NULL);

/*
 * prepare pool for the request.
 */
	apr_pool_create(&p_er, ur->pool); 
    	er = apr_palloc(p_er, sizeof(*er));
	er->pool = p_er;
	er->ur = ur;
	ur->er = er;
	er->r = NULL;	/* so that the output filter knows there is no request yet */
	er->bb_out = bb_out;
	er->bb_tmp = bb_tmp;
/*
 * read the header.
 */

	rv = epp_read(c, p_er, (char *) &framelen_n, EPP_TCP_HEADER_SIZE);
	if (rv != APR_SUCCESS)
		{
		ap_log_error(APLOG_MARK, APLOG_ERR, rv , NULL,
			"Aborting connection, couldn't read header.");

		APR_BRIGADE_INSERT_TAIL(bb_out, apr_bucket_eos_create(c->bucket_alloc));
		ap_pass_brigade(c->output_filters, bb_out);
		break;
		}

	framelen   = ntohl(framelen_n) - EPP_TCP_HEADER_SIZE;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"HEADER: length = %lu.",framelen);

	if (framelen > EPP_MAX_FRAME_SIZE)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, NULL,
			"EPP frame too large (%ld bytes). aborting.", framelen);
		APR_BRIGADE_INSERT_TAIL(bb_out, apr_bucket_eos_create(c->bucket_alloc));
		ap_pass_brigade(c->output_filters, bb_out);
		break;
		/* This will close the connection. According to the EPP standards
		 * we are *not* supposed to tell the client why we closed the connection.
		 */
	}

    	xml = apr_palloc(er->pool, framelen + 1);

	er->orig_xml = xml;
	er->orig_xml_size = framelen;
    	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);

/*
 * read the XML.
 */
	rv = epp_read(c, p_er, xml, framelen);
	if (rv != APR_SUCCESS)
		{
		ap_log_error(APLOG_MARK, APLOG_ERR, rv , NULL,
			"Aborting connection, couldn't read XML.");
		APR_BRIGADE_INSERT_TAIL(bb_out, apr_bucket_eos_create(c->bucket_alloc));
		ap_pass_brigade(c->output_filters, bb_out);
		break;
		}
	xml[framelen] = '\0';		/* just to be sure it's terminated. */

/*
 * Do the actual work.
 */

	epp_process_frame(er);

	apr_pool_destroy(p_er);


	if (ur->connection_close)
		{
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS , NULL, "Closing connection.");
		break;
		}
	}


    apr_pool_destroy(p);	/* not really needed */
    return OK;
}

/*
 * This filter prefixes each message with the epp/tcp header.
 */
static apr_status_t epp_tcp_out_filter(ap_filter_t * f, 
                                           apr_bucket_brigade * bb)
{
    epp_conn_rec *conf;
    apr_bucket *header, *flush, *bucket;
    apr_bucket_brigade *bb_tmp;
    apr_status_t rv = APR_SUCCESS;
    unsigned long len;
    apr_off_t bb_len;
    epp_user_rec *ur;
    request_rec *r;
    int found_eos = 0;
    
    ur = f->ctx;
    r = ur->er->r;
    conf = ur->conf;
    bb_tmp = ur->er->bb_tmp;

    /* 
     * No request? don't prefix
     */
    if (!r) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
   		"epp_tcp_out_filter: No request object -> passthrough.");
    	return ap_pass_brigade(f->next, bb);
    }


    /*
     * make sure the data is flushed to the client.
     */
    for (bucket = APR_BRIGADE_FIRST(bb);
	bucket != APR_BRIGADE_SENTINEL(bb);
	bucket = APR_BUCKET_NEXT(bucket)) {

       ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
                       "epp_tcp_out_filter: loop: found bucket of type %s.", bucket->type->name);


	if (APR_BUCKET_IS_EOS(bucket)) {
	        found_eos = 1;
    		ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
    			"epp_tcp_out_filter: Found an EOS bucket. Adding a FLUSH before it.");
    		flush = apr_bucket_flush_create(f->c->bucket_alloc); 
		APR_BUCKET_INSERT_BEFORE(bucket, flush);
		break;
	}
    }

    /* 
     * there could be more data coming (perhaps from a mod_proxy setup). Set the data aside 
     */
    if (!found_eos) {
    	for (bucket = APR_BRIGADE_FIRST(bb);
		bucket != APR_BRIGADE_SENTINEL(bb);
		bucket = APR_BUCKET_NEXT(bucket)) {
     /*
      * TRANSIENTS are in danger of having their memory re-used ...
      */
		if (APR_BUCKET_IS_TRANSIENT(bucket)) {
			apr_bucket_setaside(bucket, ur->er->pool);	
       			ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
	       	                "epp_tcp_out_filter: found transient, setting aside.");
		}
	}
	
	APR_BRIGADE_CONCAT(bb_tmp, bb);

	rv = apr_brigade_length(bb_tmp, 1, &bb_len);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
                       "epp_tcp_out_filter: No EOS bucket. length of bb_tmp is now %lu.", bb_len);
	return APR_SUCCESS;
    }

    /* copy back set-aside data */
    APR_BRIGADE_PREPEND(bb, bb_tmp);

    rv = apr_brigade_length(bb, 1, &bb_len);
    len = htonl(bb_len + 4);		/* len includes itself */

    /*
     * prefix only if we have data and HTTP_Ok.
     * except: implicit_login is set and we get HTTP_UNAUTHORIZED
     */
    if ((bb_len > 0) && ((r->status == HTTP_OK) || 
		((r->status == HTTP_UNAUTHORIZED) && conf->implicit_login)))
	{
    	ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
    		"epp_tcp_out_filter: Prefix = %lu bytes.", bb_len);

	r->bytes_sent += bb_len; 
	header = apr_bucket_transient_create((char *) &len, 4,  f->c->bucket_alloc);
	apr_bucket_setaside(header, f->c->pool);
	APR_BRIGADE_INSERT_HEAD(bb, header);
	}
    else
	{
	/*
	 * we don't have to actually read the buckets to clean the content as
	 * apr_brigade_length did that for us.
	 */
	ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
    		"epp_tcp_out_filter: skipping data (%lu bytes), status = %d.", bb_len, r->status);

        apr_brigade_cleanup(bb);
	}

    return ap_pass_brigade(f->next, bb);
}



/*
 * This input filter always returns EOS.
 *
 * We need this one for GET requests to avoid scripts reading from
 * our connection to the client.
 *
 */
static apr_status_t eos_in_filter(ap_filter_t * f, apr_bucket_brigade * bb,
		 ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->r->connection->bucket_alloc));

    return APR_SUCCESS;
}



/*
 * This input filter writes the xml tree from the context, then EOS.
 *
 */
static apr_status_t epp_xmlstdin_filter(ap_filter_t *f, apr_bucket_brigade *bb,
		 ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_xml_doc *doc = f->ctx;
    const char *target = NULL;
    apr_size_t tsize;

    /*
     * map xml to text ..
     */
    apr_xml_to_text(f->r->pool, doc->root, APR_XML_X2T_FULL, NULL, NULL, &target, &tsize);


    if (tsize > 0)
    	{
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(target,tsize,
		f->r->pool,f->r->connection->bucket_alloc));
	
	}


    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->r->connection->bucket_alloc));

    return APR_SUCCESS;
}



/*
 * This input filter writes the xml tree from the context as CGI parameter, 
 * the raw EPP input (if requested), the clTRID, then EOS.
 *
 */
static apr_status_t epp_xmlcgi_filter(ap_filter_t *f, apr_bucket_brigade *bb,
		 ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    epp_rec *er = f->ctx;
    epp_conn_rec *conf = er->ur->conf;

    if (er->serialised_xml_size > 0)
    	{
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_immortal_create(EPP_CONTENT_FRAME_CGI, 
				strlen(EPP_CONTENT_FRAME_CGI), f->r->connection->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(er->serialised_xml,er->serialised_xml_size,
		f->r->pool,f->r->connection->bucket_alloc));
	if (conf->raw_frame) {
		APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_immortal_create(conf->raw_frame, 
				strlen(conf->raw_frame), f->r->connection->bucket_alloc));
        	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(er->orig_xml,er->orig_xml_size,
				f->r->pool,f->r->connection->bucket_alloc));
	}
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_immortal_create(EPP_CONTENT_CLTRID_CGI, 
				strlen(EPP_CONTENT_CLTRID_CGI), f->r->connection->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(er->cltrid,strlen(er->cltrid),
		f->r->pool,f->r->connection->bucket_alloc));
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_immortal_create(EPP_CONTENT_POSTFIX_CGI, 
				strlen(EPP_CONTENT_POSTFIX_CGI), f->r->connection->bucket_alloc));
	er->serialised_xml_size = 0;    /* don't send content twice if called twice. */
	}

    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->r->connection->bucket_alloc));
    return APR_SUCCESS;
}


static void register_hooks(apr_pool_t *p)
{

    ap_hook_process_connection(epp_process_connection,NULL,NULL,
			       APR_HOOK_MIDDLE);
    ap_register_output_filter("EPPTCP_OUTPUT", epp_tcp_out_filter, NULL,
		                                   AP_FTYPE_CONNECTION);
    ap_register_input_filter("EOS_INPUT", eos_in_filter, NULL,
		                                   AP_FTYPE_PROTOCOL);
    ap_register_input_filter("XML_INPUT", epp_xmlstdin_filter, NULL,
		                                   AP_FTYPE_PROTOCOL);
    ap_register_input_filter("XMLCGI_INPUT", epp_xmlcgi_filter, NULL,
		                                   AP_FTYPE_PROTOCOL);

}

static void *epp_create_server(apr_pool_t *p, server_rec *s)
{
    epp_conn_rec *conf = (epp_conn_rec *)apr_pcalloc(p, sizeof(*conf));

    conf->epp_on 		= 0;
    conf->implicit_login	= 0;
    conf->command_root 		= EPP_DEFAULT_COMMAND_ROOT;
    conf->session_root 		= EPP_DEFAULT_SESSION_ROOT;
    conf->error_root 		= EPP_DEFAULT_ERROR_ROOT;
    conf->authuri 		= EPP_DEFAULT_AUTH_URI;
    conf->rc_header 		= EPP_DEFAULT_RC_HEADER;
    conf->raw_frame 		= NULL;
    return conf;
}

static const char *set_epp_protocol(cmd_parms *cmd, void *dummy, int flag)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }

    conf->epp_on = flag;
    return NULL;
}


static const char *set_epp_command_root(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    conf->command_root = apr_pstrdup(cmd->pool, arg);
    return NULL;
}


static const char *set_epp_session_root(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    conf->session_root = apr_pstrdup(cmd->pool, arg);
    return NULL;
}


static const char *set_epp_error_root(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    conf->error_root = apr_pstrdup(cmd->pool, arg);
    return NULL;
}



static const char *set_epp_authuri(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }

    if (!strcmp(arg, "implicit")) {	/* authentication is done by <login> itself */
	conf->implicit_login = 1;
    } else {
	conf->authuri = apr_pstrdup(cmd->pool, arg);
	conf->implicit_login = 0;
    }
    return NULL;
}


static const char *set_epp_rc_header(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    conf->rc_header = apr_pstrdup(cmd->pool, arg);
    return NULL;
}


static const char *set_epp_raw_frame(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    conf->raw_frame = apr_psprintf(cmd->pool, EPP_CONTENT_RAW_CGI, arg);
    return NULL;
}

static const command_rec epp_cmds[] = {
    AP_INIT_FLAG("EPPEngine", set_epp_protocol, NULL, RSRC_CONF,
                 "Whether this server is using EPP"),
    AP_INIT_TAKE1("EPPCommandRoot",set_epp_command_root , NULL, RSRC_CONF,
		                      "Baseline URI for EPP command translation."),
    AP_INIT_TAKE1("EPPSessionRoot",set_epp_session_root , NULL, RSRC_CONF,
		                      "Baseline URI for EPP session handling requests."),
    AP_INIT_TAKE1("EPPErrorRoot",set_epp_error_root , NULL, RSRC_CONF,
		                      "Baseline URI for EPP error handling."),
    AP_INIT_TAKE1("EPPAuthURI",set_epp_authuri , NULL, RSRC_CONF,
		                      "URI for authentication requests."),
    AP_INIT_TAKE1("EPPReturncodeHeader",set_epp_rc_header , NULL, RSRC_CONF,
		                      "Which header contains the EPP returncode"),
    AP_INIT_TAKE1("EPPRawFrame",set_epp_raw_frame , NULL, RSRC_CONF,
		                      "Pass the original EPP frame as which CGI parameter?"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA epp_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    epp_create_server,		/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    epp_cmds,			/* command apr_table_t */
    register_hooks		/* register hooks */
};

