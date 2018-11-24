//
// Created by root on 18-11-24.
//

#ifndef NGINX_MONITOR_NGX_HTTP_MYTEST_MODULE_H
#define NGINX_MONITOR_NGX_HTTP_MYTEST_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);

//配置项中出现mytest时调用该方法【在ngx_command_t中】
static char* ngx_http_mytest(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
//对应的URL匹配与location的匹配时，调用该方法【在ngx_http_mytest中设置】
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);


//ngx_http_upstream_t结构体中的３个回调方法
void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r);
//用于解析上游服务器返回的基于ＴＣＰ的响应头部
ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r);


//建立mytest配置项的参数的结构体
typedef struct{
	ngx_str_t my_test;
	ngx_http_upstream_conf_t upstream;
}ngx_http_mytest_conf_t;


//建立mytest模块的上下文结构体
typedef struct{
	ngx_uint_t my_step;
}ngx_http_mytest_ctx_t;

static ngx_command_t ngx_http_mytest_commands[]={
	{
		ngx_string("mytest"),
		NGX_HTTP_MAIN_CONF| NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_http_mytest,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_mytest_conf_t,my_test),
		//		0,
		NULL
	},
	//以上是一个mytest的配置项。并设置了 ： 该配置项的配置及处理函数

	//upstream_connect_timeout配置项
	{	//设置connect_timeout连接超时时间
		ngx_string("upstream_connect_timeout"),
		NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		//给出connect_timeout成员在ngx_http_mystream_conf_t结构体中的偏移字节数
		offsetof(ngx_http_mytest_conf_t,upstream.connect_timeout),
		NULL
	},

	ngx_null_command
};

static ngx_http_module_t ngx_http_mytest_module_ctx={
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		//	NULL,
		ngx_http_mytest_create_loc_conf,
		NULL
};

ngx_module_t ngx_http_mytest_module= {
		NGX_MODULE_V1,
		&ngx_http_mytest_module_ctx,
		ngx_http_mytest_commands,
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


#endif //NGINX_MONITOR_NGX_HTTP_MYTEST_MODULE_H
