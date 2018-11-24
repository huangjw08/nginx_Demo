//
// Created by root on 18-11-5.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_mytest(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);

//建立mytest配置项的参数的结构体
typedef struct{
	ngx_str_t my_test;
//	ngx_http_upstream_conf_t upstream;
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


static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf){
	ngx_http_mytest_conf_t *mycf;
	mycf=ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
	if (mycf==NULL){
		return NGX_CONF_ERROR;
	}
	mycf->my_test.data=NULL;
	mycf->my_test.len=0;
	return mycf;
}



static char* ngx_http_mytest(ngx_conf_t *cf,ngx_command_t *cmd,void *conf){
	ngx_conf_set_str_slot(cf,cmd,conf);
	ngx_http_core_loc_conf_t *clcf;
	clcf=ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler=ngx_http_mytest_handler;
	return NGX_CONF_OK;
}


static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r){
	if(!(r->method&(NGX_HTTP_GET|NGX_HTTP_HEAD))){
		return NGX_HTTP_NOT_ALLOWED;
	}

	ngx_int_t rc=ngx_http_discard_request_body(r);
	if (rc!=NGX_OK){
		return rc;
	}
	ngx_str_t type=ngx_string("text/plain");

	ngx_http_mytest_conf_t *mytest;
	mytest=ngx_http_get_module_loc_conf(r,ngx_http_mytest_module);
	ngx_str_t response;
	//mytest->my_test.data获取的是nginx.conf中mytest配置项的参数

	if (0==ngx_strncmp(mytest->my_test.data,"yes",mytest->my_test.len)){
		ngx_str_set(&response,"Hello World"+r->args.len);
	}else{
		ngx_str_set(&response,r->args.data);
	}

	r->headers_out.status=NGX_HTTP_OK;
	r->headers_out.content_length_n=response.len;
	r->headers_out.content_type=type;

	rc=ngx_http_send_header(r);
	if (rc==NGX_ERROR||rc>NGX_OK||r->header_only){
		return rc;
	}

	ngx_buf_t *b;
	b=ngx_create_temp_buf(r->pool,response.len);
	if (b==NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_memcpy(b->pos,response.data,response.len);
	b->last=b->pos+response.len;
	b->last_buf=1;

	ngx_chain_t out;
	out.buf=b;
	out.next=NULL;

	return ngx_http_output_filter(r,&out);

}

