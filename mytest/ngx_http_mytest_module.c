//
// Created by root on 18-11-5.
//
#include "ngx_http_mytest_module.h"


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
	ngx_http_core_loc_conf_t *clcf;
	clcf=ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler=ngx_http_mytest_handler;
	ngx_conf_set_str_slot(cf,cmd,conf);
	return NGX_CONF_OK;
}


static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r){
	if(!(r->method&(NGX_HTTP_GET|NGX_HTTP_HEAD))){
		return NGX_HTTP_NOT_ALLOWED;
	}

	//丢弃包体
	ngx_int_t rc=ngx_http_discard_request_body(r);
	if (rc!=NGX_OK){
		return rc;
	}

	//开始准备向用户发送响应

	//ngx_str_t的初始化宏ngx_string,一次性设置好data和len
	ngx_str_t type=ngx_string("text/plain");

	//读取nginx.conf中mytest配置项的参数.
	ngx_http_mytest_conf_t *mytest;
	mytest=ngx_http_get_module_loc_conf(r,ngx_http_mytest_module);

//	r->upstream->conf=&mytest->upstream;


//	r->upstream->create_request=mytest_upstream_create_request;
//	r->upstream->process_header=mytest_upstream_process_header;
//	r->upstream->finalize_request=mytest_upstream_finalize_request;



	ngx_str_t response;
	//mytest->my_test.data获取的是nginx.conf中mytest配置项的参数

	if (0==ngx_strncmp(mytest->my_test.data,"yes",mytest->my_test.len)){
		ngx_str_set(&response,"Hello World");
	}else{
		ngx_str_set(&response,r->args.data);
	}

	ngx_log_error_core(NGX_LOG_DEBUG,r->connection->log,0,"mytest->my_test.len=%d, mytest->mytest=%V",mytest->my_test.len,&mytest->my_test);


	//设置返回的状态码
	r->headers_out.status=NGX_HTTP_OK;
	//响应包是有包体内容的，需要设置Content-Length长度[返回的长度！！]
	r->headers_out.content_length_n=r->args.len;
	//设置Content-Type
	r->headers_out.content_type=type;

	//发送HTTP头部
	rc=ngx_http_send_header(r);
	if (rc==NGX_ERROR||rc>NGX_OK||r->header_only){
		return rc;
	}

	ngx_log_error_core(NGX_LOG_DEBUG,r->connection->log,0,"r->args.len=%d, r->args.data=%s",r->args.len,r->args.data);
	//不知道为什么response.len总是直接就等于7.....
	response.len=r->args.len;
	ngx_log_error_core(NGX_LOG_DEBUG,r->connection->log,0,"response.len=%d, response.data=%s",response.len,response.data);

	//将内存中的字符串作为包体发送。
	ngx_buf_t *b;
	//nginx中采用内存池管理，在请求结束时，内存池分配的内存将被释放 书P102
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

