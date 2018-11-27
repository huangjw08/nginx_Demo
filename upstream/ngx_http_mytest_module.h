//
// Created by root on 18-11-27.
//

#ifndef NGINX_MONITOR_NGX_HTTP_MYTEST_MODULE_H
#define NGINX_MONITOR_NGX_HTTP_MYTEST_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_http_upstream_conf_t upstream;
} mytest_conf_t;

//请求上下文结构体
typedef struct {
	ngx_http_status_t status;
	ngx_str_t backendServer;
} mytest_ctx_t;

static void *mytest_create_loc_conf(ngx_conf_t *cf);
static char *mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r);

//用来解析HTTP响应行
static ngx_int_t mytest_upstream_process_status_line(ngx_http_request_t *r);

//用来解析Http响应头部
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r);


static void mytest_upstream_finalize_request(ngx_http_request_t *r,
											 ngx_int_t rc);
static ngx_int_t mytest_handler(ngx_http_request_t *r);
static char *mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_http_module_t mytest_ctx = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	mytest_create_loc_conf,
	mytest_merge_loc_conf
};

static ngx_command_t mytest_commands[] = {
	{
		ngx_string("mytest"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
		mytest,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command
};

ngx_module_t ngx_http_mytest_module = {
	NGX_MODULE_V1,
	&mytest_ctx,
	mytest_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};


//可用来屏蔽后端服务器的响应头？
static ngx_str_t  mytest_upstream_hide_headers[] =
{
	ngx_string("Date"),
	ngx_string("Server"),
	ngx_string("X-Pad"),
	ngx_string("X-Accel-Expires"),
	ngx_string("X-Accel-Redirect"),
	ngx_string("X-Accel-Limit-Rate"),
	ngx_string("X-Accel-Buffering"),
	ngx_string("X-Accel-Charset"),
	ngx_null_string
};


#endif //NGINX_MONITOR_NGX_HTTP_MYTEST_MODULE_H
