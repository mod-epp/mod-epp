
/*
 * This code is copyright NIC.at.
 *
 * Written by Otmar Lendl <lendl@nic.at>
 *
 * We intend to release this code under the Apache licence.
 * A more formal copyright notice will appear in future releases,
 * this is just a quick placeholder to get the code out at all.
 *
 * /ol/2k2/11/06/
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
#include "mod_epp.h"

#include <sys/types.h>

module AP_MODULE_DECLARE_DATA epp_module;

static epp_rec greeting_rec;

/* from mod_jabber */

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


static request_rec *epp_create_request(epp_user_rec *ur)
{
apr_pool_t *p;
request_rec *r;

apr_pool_create(&p, ur->pool);

r                  = apr_pcalloc(p, sizeof(*r));
r->pool            = p;
r->connection      = ur->c;
r->server          = ur->c->base_server;

ur->c->keepalive   = 0;

r->user            = "tag-user";
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

r->sent_bodyct     = 0;                      /* bytect isn't for body */

r->output_filters  = ur->c->output_filters;
r->input_filters   = ur->c->input_filters;

r->status = HTTP_OK;                         /* Until further notice. */
r->request_time	   = apr_time_now();

ap_set_module_config(r->request_config, &epp_module, ur);

return r;
}

/*
 * Take an epp request struct and try to find the clTRID.
 *
 */
apr_status_t epp_get_cltrid(epp_rec *er)
{
apr_xml_elem *id,*root,*e;
apr_text *t;
size_t n;

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

/*
 * actually, this is probably overkill, we just get < 64 chars
 * in one text entry as we xml-parse in one go.
 */

n = sizeof(er->cltrid) - 1;
for (t = id->first_cdata.first; t; t = t->next) 
	{
	strncat(er->cltrid, t->text, n);
	n -= strlen(t->text);
	if (n < 1) break;
	}

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
 */

epp_translate_xml_to_uri(apr_xml_doc *doc, char *b, apr_size_t b_size, epp_rec *er)
{
apr_xml_elem *cred, *command, *c, *hello;
epp_conn_rec *conf = er->ur->conf;

/*
 * default to a schema error
 */
strncpy(b, conf->xml_error_schema, b_size);

if(strcmp("epp",doc->root->name))
	return(APR_BADARG);
/*
 * Check for a hello frame
 */

hello = get_elem(doc->root->first_child, "hello");
if (hello != NULL)
	{
	apr_snprintf(b, b_size, "%s/hello", conf->command_root);
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
	if (!strcasecmp(c->name, "clTRID")) 
		{
		c = c->next;
		continue;
		}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"XML: found command = %s.", c->name);
	apr_snprintf(b, b_size, "%s/%s", conf->command_root, c->name);
	c = c->next;
	}

/* XXX doesn't handle empty command gacefully */
return(APR_SUCCESS);
}


/*
 * Call an error handler.
 *
 */
apr_status_t epp_error_handler(epp_rec *er, char *uri, char *errmsg)
{
request_rec *r, *rr;

r = epp_create_request(er->ur);
ap_add_input_filter("EOS_INPUT", (void *) er, r, r->connection);
rr = ap_sub_req_method_uri("GET", uri, r, er->ur->c->output_filters);
ap_run_sub_req(rr);
ap_fflush(er->ur->c->output_filters, er->bb_out);
if (rr != NULL) 
	ap_destroy_sub_req(rr);

}

/*
 * This is the core function. 
 *
 * We have to a full EPP frame, now build the XML object,
 * do some rudimentary checking, build an URI, an request
 * object and call it.
 *
 */
epp_process_frame(epp_rec *er)
{
apr_xml_parser *xml_p;
apr_xml_doc *doc;
apr_status_t rv;
char errstr[300];
request_rec *r, *rr;
int retval;
epp_conn_rec *conf = er->ur->conf;

char uri[200];
char content_length[20];

xml_p = apr_xml_parser_create(er->pool);
rv = apr_xml_parser_feed(xml_p, er->orig_xml, er->orig_xml_size);
apr_xml_parser_geterror(xml_p, errstr, sizeof(errstr));
ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
	"XML parser feed reports: %s", errstr);

rv = apr_xml_parser_done(xml_p,&doc);
er->doc = doc;

apr_xml_parser_geterror(xml_p, errstr, sizeof(errstr));
ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
	"XML parser done reports: %s", errstr);


if (rv != APR_SUCCESS)
	{
	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, NULL,
		"not valid XML");
	epp_error_handler(er, conf->xml_error_parse, errstr);
	return;
	}

rv = epp_get_cltrid(er);
if (rv != APR_SUCCESS)
	{
	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, NULL,
		"Schema error while looking for clTRID");
	epp_error_handler(er, conf->xml_error_schema, "Schema error while looking for clTRID");
	return;
	}

/*
 * now do the actual work
 */

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"XML: root node name = %s.", doc->root->name);


	r = epp_create_request(er->ur);
	
        apr_xml_to_text(r->pool,doc->root,APR_XML_X2T_FULL_NS_LANG, doc->namespaces ,NULL, &er->serialised_xml, 
				&er->serialised_xml_size);

/*
 * There seems to be a bug somewhere in the size calculations. 
 * If I use the returned serialised_xml_size, I get trailing garbage every now and then.
 * *shrug*, the let's go for strlen, as I hope that there are no null bytes in the XML.
 */
	er->serialised_xml_size = strlen(er->serialised_xml);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"XML: serialized xml size = %d.", er->serialised_xml_size);
	sprintf(content_length, "%u", strlen(EPP_CONTENT_FRAME_CGI) 
				+ strlen(EPP_CONTENT_CLTRID_CGI) 
				+ strlen(er->cltrid) 
				+ strlen(EPP_CONTENT_POSTFIX_CGI)
				+ er->serialised_xml_size);

	apr_table_set(r->headers_in, "Content-Type", "multipart/form-data; boundary=--BOUNDARY--");
	apr_table_set(r->headers_in, "Content-Length", content_length);

	ap_add_input_filter("XMLCGI_INPUT", (void *) er, r, r->connection);

	epp_translate_xml_to_uri(doc, uri, sizeof(uri), er);
        rr = ap_sub_req_method_uri("POST", uri, r, er->ur->c->output_filters);
	rr->the_request = uri;
	retval = ap_run_sub_req(rr);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"ap_run_sub_req returned %d", retval);
/*	rr->request_time	   = apr_time_now(); */
	/*
	 * make sure the error status is logged correctly.
	 */
	if(retval) 
		rr->status = retval;
	ap_run_log_transaction(rr); 
	/*
	 * did it work?
	 */
	if (retval != 0)
		{
		ap_fputs(er->ur->c->output_filters, er->bb_out, "<epp> ERROR </epp>");
		ap_fflush(er->ur->c->output_filters, er->bb_out);
		}

	ap_fflush(er->ur->c->output_filters, er->bb_out);
	if (rr != NULL) 
		ap_destroy_sub_req(rr);
}

static int process_epp_connection(conn_rec *c)
{
    server_rec *s = c->base_server;
    request_rec *r;
    epp_user_rec *ur;
    epp_rec *er;
    epp_rec greeting_er;
    unsigned long framelen, framelen_n;
    apr_pool_t *p;
    apr_bucket_brigade *bb_in;
    apr_bucket_brigade *bb_tmp;
    apr_bucket_brigade *bb_out;
    apr_bucket *e,*prev_e,*next_e;
    apr_status_t rv;
    apr_off_t bb_len;


    int count =  0;
    const char *str;
    apr_size_t len;

    char *xml;

    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);

    if (!conf->epp_on) {
        return DECLINED;
    }

    ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);
    ap_add_output_filter("EPPTCP_OUTPUT", NULL, NULL, c);
    ap_add_input_filter("EPPTCP_INPUT", NULL, NULL, c);

    apr_pool_create(&p, c->pool);
    ur 		= apr_palloc(p, sizeof(*ur));
    ur->pool 	= p;
    ur->c 	= c;
    ur->conf	= conf;


    /* create the brigades */

    bb_in = apr_brigade_create(ur->pool, c->bucket_alloc);
    bb_out = apr_brigade_create(ur->pool, c->bucket_alloc);
    bb_tmp = apr_brigade_create(ur->pool, c->bucket_alloc);


    /* send greeting */
    apr_pool_create(&p, ur->pool);
    er = apr_palloc(p, sizeof(*er));
    er->pool = p;
    er->ur = ur;
    er->bb_out = bb_out;
    er->orig_xml = EPP_BUILTIN_HELLO;
    er->orig_xml_size = strlen(EPP_BUILTIN_HELLO);
    epp_process_frame(er);



    /* loop over all epp frames */
    for ( ; ; )
	{
/*
 * not enough data to read a complete header?
 */
	while( (rv = apr_brigade_length(bb_in, 1, &bb_len), bb_len ) < EPP_TCP_HEADER_SIZE ) 
		{
		if ((rv = ap_get_brigade(c->input_filters, bb_tmp, AP_MODE_READBYTES,
			APR_BLOCK_READ, EPP_CHUNK_SIZE) != APR_SUCCESS ||
			APR_BRIGADE_EMPTY(bb_tmp))) 
			{
			ap_log_error(APLOG_MARK, APLOG_ERR, rv , NULL,
				"Error reading EPP header. Aborting connection.");
			apr_brigade_destroy(bb_tmp);
    			APR_BRIGADE_INSERT_TAIL(bb_out, apr_bucket_eos_create(c->bucket_alloc));
			ap_pass_brigade(c->output_filters, bb_out);
			goto close_connection;
			}

		e = APR_BRIGADE_FIRST(bb_tmp);
		if (APR_BUCKET_IS_EOS(e) || APR_BUCKET_IS_FLUSH(e)) 
			{
	/* EOS or similar? return it through output filter */
			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(bb_out, e);
			ap_pass_brigade(c->output_filters, bb_out);
			return APR_SUCCESS;
			}

		APR_BRIGADE_CONCAT(bb_in, bb_tmp);   

		apr_brigade_length(bb_in, 1, &bb_len);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
			"apr_brigade_length returned %ld", bb_len);
		}


/*
 * we have enough data in the brigade, so read header.
 */
	len = EPP_TCP_HEADER_SIZE;
	apr_brigade_flatten(bb_in, (char *) &framelen_n, &len);

	framelen   = ntohl(framelen_n) - EPP_TCP_HEADER_SIZE;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"HEADER: length = %u.",framelen);
/*
 * Remove the header from the brigade
 *
 */
	apr_brigade_partition(bb_in, EPP_TCP_HEADER_SIZE, &next_e);
	while (!APR_BRIGADE_EMPTY(bb_in)) 
		{
		e = APR_BRIGADE_FIRST(bb_in);
		if (e == next_e) break;
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
			"POST-HEADER: removing one bucket (length = %u).",e->length);
		apr_bucket_delete(e);
		}

	if (framelen > EPP_MAX_FRAME_SIZE)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, NULL,
			"EPP frame too large (%ld bytes). aborting.", framelen);
		return(OK);
	}

    	apr_pool_create(&p, ur->pool);
    	er = apr_palloc(p, sizeof(*er));
	er->pool = p;
	er->ur = ur;
	er->bb_out = bb_out;

    	xml = apr_palloc(er->pool, framelen + 1);

	er->orig_xml = xml;
	er->orig_xml_size = framelen;

/*
 * Do we need more data in the brigade?
 *
 * If yes, get a new one and concat them.
 *
 */
	while( (rv = apr_brigade_length(bb_in, 1, &bb_len), bb_len ) < framelen ) 
	{
	if ((rv = ap_get_brigade(c->input_filters, bb_tmp, AP_MODE_READBYTES,
		APR_BLOCK_READ, EPP_CHUNK_SIZE) != APR_SUCCESS ||
		APR_BRIGADE_EMPTY(bb_tmp))) 
		{
		ap_log_error(APLOG_MARK, APLOG_ERR, rv , NULL,
			"Error reading EPP frame. Aborting connection.");
		apr_brigade_destroy(bb_tmp);
		APR_BRIGADE_INSERT_TAIL(bb_out, apr_bucket_eos_create(c->bucket_alloc));
		ap_pass_brigade(c->output_filters, bb_out);
		goto close_connection;
		return OK;
		}
	APR_BRIGADE_CONCAT(bb_in, bb_tmp);   
	}

/*
 * We now have enough data in the brigade. Copy it over to the xml string.
 *
 */

	len = framelen;
	apr_brigade_flatten(bb_in, xml, &len);
	xml[framelen] = '\0';

/*	fprintf(stderr, "Read %ld bytes of XML: \n--->%s<----\n", framelen, xml); */

/*
 * Do the actual work.
 */

	epp_process_frame(er);


/*
 * Now we have to get rid of the first framelen bytes from the brigade
 *
 */
	apr_brigade_partition(bb_in, framelen, &next_e);
	while (!APR_BRIGADE_EMPTY(bb_in)) 
		{
		e = APR_BRIGADE_FIRST(bb_in);
		if (e == next_e) break;
/*		ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
			"POST-FRAME: removing one bucket (length = %u).",e->length);
*/
		apr_bucket_delete(e);
		}

	apr_brigade_length(bb_in, 1, &bb_len);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
		"Finished processing EPP frame. %ld bytes left in brigade.", bb_len);
	}

close_connection:
    return OK;
}


/*
 * This filter prefixes each message with the epp/tcp header.
 */
static apr_status_t epp_tcp_out_filter(ap_filter_t * f, 
                                           apr_bucket_brigade * bb)
{
    apr_bucket *header;
    apr_status_t rv;
    const char *buf;
    const char *pos;
    unsigned long len;
    apr_off_t bb_len;
 
    rv = apr_brigade_length(bb, 1, &bb_len);
    len = htonl(bb_len + 4);		/* len includes itself */

    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv , NULL,
    	"epp_tcp_out_filter: %ld bytes in brigade.", bb_len);
    if (bb_len > 0)
	{
	header = apr_bucket_transient_create((char *) &len, 4,  f->c->bucket_alloc);
	apr_bucket_setaside(header, f->c->pool);
	APR_BRIGADE_INSERT_HEAD(bb, header);
	}

    return ap_pass_brigade(f->next, bb);
}


/*
 * This input filter reads a epp/tcp frame, waits for it to be complete
 * and then strip out the header.
 *
 * DUMMY FUNCTION FOR NOW. NOTHING DONE HERE
 *
 */
static apr_status_t epp_tcp_in_filter(ap_filter_t * f, apr_bucket_brigade * bb,
		 ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *header;
    apr_status_t rv;
    const char *buf;
    const char *pos;
    unsigned long len;
    apr_off_t bb_len;

    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
    return rv;
}



/*
 * This input filter always returns EOS
 *
 */
static apr_status_t eos_in_filter(ap_filter_t * f, apr_bucket_brigade * bb,
		 ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *header;
    apr_status_t rv;
    const char *buf;
    const char *pos;
    unsigned long len;
    apr_off_t bb_len;

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
    apr_bucket *header;
    apr_status_t rv;
    const char *buf;
    const char *pos;
    unsigned long len;
    apr_off_t bb_len;
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
 * the clTRID, then EOS.
 *
 */
static apr_status_t epp_xmlcgi_filter(ap_filter_t *f, apr_bucket_brigade *bb,
		 ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *header;
    apr_status_t rv;
    const char *buf;
    const char *pos;
    unsigned long len;
    apr_off_t bb_len;
    epp_rec *er = f->ctx;

    if (er->serialised_xml_size > 0)
    	{
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_immortal_create(EPP_CONTENT_FRAME_CGI, 
				strlen(EPP_CONTENT_FRAME_CGI), f->r->connection->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(er->serialised_xml,er->serialised_xml_size,
		f->r->pool,f->r->connection->bucket_alloc));
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_immortal_create(EPP_CONTENT_CLTRID_CGI, 
				strlen(EPP_CONTENT_CLTRID_CGI), f->r->connection->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(er->cltrid,strlen(er->cltrid),
		f->r->pool,f->r->connection->bucket_alloc));
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_immortal_create(EPP_CONTENT_POSTFIX_CGI, 
				strlen(EPP_CONTENT_POSTFIX_CGI), f->r->connection->bucket_alloc));
	}

    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->r->connection->bucket_alloc));
    return APR_SUCCESS;
}


static void register_hooks(apr_pool_t *p)
{

    ap_hook_process_connection(process_epp_connection,NULL,NULL,
			       APR_HOOK_MIDDLE);
    ap_register_output_filter("EPPTCP_OUTPUT", epp_tcp_out_filter, NULL,
		                                   AP_FTYPE_CONNECTION);
    ap_register_input_filter("EPPTCP_INPUT", epp_tcp_in_filter, NULL,
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

    conf->epp_on = 0;
    conf->xml_error_parse 	= EPP_DEFAULT_XML_ERROR;
    conf->xml_error_schema 	= EPP_DEFAULT_XML_ERROR_SCHEMA;
    conf->command_root 		= EPP_DEFAULT_COMMAND_ROOT;
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


static const char *set_epp_xml_error_parse(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    conf->xml_error_parse = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *set_epp_xml_error_schema(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    epp_conn_rec *conf = (epp_conn_rec *)ap_get_module_config(s->module_config,
                                                              &epp_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    conf->xml_error_schema = apr_pstrdup(cmd->pool, arg);
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



static const command_rec epp_cmds[] = {
    AP_INIT_FLAG("EPPProtocol", set_epp_protocol, NULL, RSRC_CONF,
                 "Whether this server is serving the EPP protocol"),
    AP_INIT_TAKE1("EPPXMLParseError",set_epp_xml_error_parse , NULL, RSRC_CONF,
		                      "Error URI for XML parsing errors"),
    AP_INIT_TAKE1("EPPXMLNotEPP",set_epp_xml_error_schema , NULL, RSRC_CONF,
		                      "Error URI for XML ok, but not <epp>"),
    AP_INIT_TAKE1("EPPCommandRoot",set_epp_command_root , NULL, RSRC_CONF,
		                      "Baseline URI for EPP command translation"),
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


/* HALDE **************************/



/*
if(strcmp("epp",doc->root->name))
	{
	ap_epp_tcp_sendelement(f, bb, "<error>Not epp</error>\n");
	return;
	}

command = get_elem(doc->root->first_child, "command");
if (command == NULL)
	{
	ap_epp_tcp_sendelement(f, bb, "<error>no command?</error>\n");
        return;
	}

c = command->first_child;
while (c != NULL)
{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, NULL,
		"XML: found command = %s.", c->name);
	c = c->next;
}

cred = get_elem(command->first_child, "cred");


apr_status_t ap_epp_tcp_sendelement(ap_filter_t *f, apr_bucket_brigade *bb, char *e)   
{
unsigned long len;
apr_status_t rv;
 
len = htonl(strlen(e) + 4);		

rv = ap_fputs(f, bb, e);

rv = ap_fflush(f, bb);

return(rv);
}

*/

