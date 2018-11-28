
#include "ngx_http_mytest_module.h"


static void *mytest_create_loc_conf(ngx_conf_t *cf){
	mytest_conf_t *mycf;
	mycf = (mytest_conf_t *)ngx_pcalloc(cf->pool, sizeof(mytest_conf_t));
	if(mycf == NULL){
		return NULL;
	}

	//对mytest_conf_t结构中ngx_http_upstream_conf_t类型的各个成员硬编码，超时时间设为1分钟
	mycf->upstream.connect_timeout = 60000;
	mycf->upstream.send_timeout = 60000;
	mycf->upstream.read_timeout = 60000;
	mycf->upstream.store_access = 0600;

	mycf->upstream.buffering = 0; //buffering为0时，表示以固定大小将后端服务器的响应 ---> 客户端
	mycf->upstream.bufs.num = 8;
	mycf->upstream.bufs.size = ngx_pagesize;
	mycf->upstream.buffer_size = ngx_pagesize;
	mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
	mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
	mycf->upstream.max_temp_file_size = 1024 * 1024 *1024;

	mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
	mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

	return mycf;
}

static char *mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child){
	mytest_conf_t *prev = (mytest_conf_t *)parent;
	mytest_conf_t *conf = (mytest_conf_t *)child;


	ngx_hash_init_t hash;
	hash.max_size = 100;
	hash.bucket_size = 1024;
	hash.name = "proxy_headers_hash";

	/*
	 * 此处的ngx_http_upstream_hide_headers_hash()必须在merge_loc_conf()中调用
	 */
	if(ngx_http_upstream_hide_headers_hash(cf,&conf->upstream, &prev->upstream,mytest_upstream_hide_headers,&hash)!=NGX_OK){
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}

static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r){
	static ngx_str_t backendQueryLine = ngx_string("GET /s?wd=%V HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");
	ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;

	ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
	if(b == NULL) return NGX_ERROR;
	b->last = b->pos + queryLineLen;

	ngx_snprintf(b->pos, queryLineLen, (char *)backendQueryLine.data, &r->args);

	//ngx_chain_t类型也要通过r->pool内存池进行分配
	r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
	if(r->upstream->request_bufs == NULL) return NGX_ERROR;

	r->upstream->request_bufs->buf = b;
	r->upstream->request_bufs->next = NULL;

	r->upstream->request_sent = 0;
	r->upstream->header_sent = 0;

	//header_hash不可以为0  书P171
	r->header_hash = 1;

	return NGX_OK;
}


//这个是收到了来自后端服务器的响应后，才调用的这个方法的
static ngx_int_t mytest_upstream_process_status_line(ngx_http_request_t *r){
	size_t len;
	ngx_int_t rc;
	ngx_http_upstream_t *u;

	//上下文中才会保存多次解析HTTP响应行的状态，首先要取出请求的上下文。
	mytest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
	if(ctx == NULL) return NGX_ERROR;

	u = r->upstream;

	//上下文传入的参数为： 收到的字符流和上下文ngx_http_status_t结构
	rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

	//表示还没解析出完整的HTTP响应行，需要接受更多的字符流再进行解析
	if(rc == NGX_AGAIN) return rc;
	//返回NGX_ERROR时，表示没有接收到合法的HTTP响应行
	if(rc == NGX_ERROR){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");

		r->http_version = NGX_HTTP_VERSION_9;
		u->state->status = NGX_HTTP_OK;

		return NGX_OK;
	}


	/**
	 * 将解析出的信息设置到r->upstream->headers_in 结构体,
	 * 解析完所有包头后，再把headers_in中的成员设置到将要向下游发送的r->headers_out结构体中
	 */

	if(u->state){
		/*
		 * ngx_http_upstream_state_t *state;
		 * ngx_http_status_t status;
		 * ngx_uint_t           code;
		 */

		u->state->status = ctx->status.code;
	}

	u->headers_in.status_n = ctx->status.code;
	len = ctx->status.end - ctx->status.start;
	u->headers_in.status_line.len = len;
	u->headers_in.status_line.data = ngx_pcalloc(r->pool, len);
	if(u->headers_in.status_line.data == NULL) return NGX_ERROR;

	ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"HHHH: ctx->status.start=%s",ctx->status.start);

	ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

	ngx_log_error_core(NGX_LOG_DEBUG,r->connection->log,0,"u->headers_in.status_line=%V",&u->headers_in.status_line);

	//下一步将解析HTTP头部，设置process_header回调方法为mytest_upstream_process_header()
	//即之后接受到的字符流将交给mytest_upstream_process_header()进行解析.
	u->process_header = mytest_upstream_process_header;

	return mytest_upstream_process_header(r);
}

static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r){
	ngx_int_t rc;
	ngx_table_elt_t *h;
	ngx_http_upstream_header_t *hh;
	ngx_http_upstream_main_conf_t *umcf;//对将要转发给下游客户端的HTTP响应头部进行统一处理。该结构体中存储了需要进行统一处理的HTTP头部名称和回调方法。

	umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

	//循环解析所有的HTTP头部
	for(;;){
		//HTTP框架提供的ngx_http_parse_header_line()，用于解析HTTP头部
		rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
		//返回NGX_OK时，表示解析出一行HTTP头部
		if(rc == NGX_OK){
			//向headers_in.headers这个ngx_list_t链表中添加HTTP头部
			//ngx_list_push()该函数在给定的list的尾部追加一个元素,并返回指向新元素存放空间的指针。如果追加失败,则返回NULL

			//========================================
			h = ngx_list_push(&r->upstream->headers_in.headers);
			if(h == NULL) return NGX_ERROR;

			h->hash = r->header_hash;
			h->key.len = r->header_name_end - r->header_name_start;
			h->value.len = r->header_end - r->header_start;

			h->key.data = ngx_pcalloc(r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
			if(h->key.data == NULL) return NGX_ERROR;

			h->value.data = h->key.data + h->key.len + 1;
			h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

			ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
			h->key.data[h->key.len]='\0';
			ngx_memcpy(h->value.data, r->header_start, h->value.len);
			h->value.data[h->value.len] = '\0';

			if(h->key.len == r->lowcase_index){
				ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
			}else{
				ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
			}
			//==============以上这段代码就是在设置ngx_table_elt_t中的各个成员=======================

			//upstream模块对一些HTTP头部做特殊处理
			hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
			if(hh && hh->handler(r, h, hh->offset)!=NGX_OK) return NGX_ERROR;

			continue;
		}


		//表示响应中所有的HTTP头部都已解析完毕，接下来再接收到的就是HTTP包体
		if(rc == NGX_HTTP_PARSE_HEADER_DONE){
			/* 如果之前解析HTTP头部时没有发现server和date头部，那么下面会根据HTTP协议规范添加这两个头部
			 *
			 */
			if(r->upstream->headers_in.server == NULL){
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if(h == NULL) return NGX_ERROR;
				h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
				ngx_str_set(&h->key, "Server");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *)"server";
			}

			if(r->upstream->headers_in.date == NULL){
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if(h == NULL) return NGX_ERROR;
				h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
				ngx_str_set(&h->key, "Date");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *)"date";
			}
			return NGX_OK;
		}
		if(rc == NGX_AGAIN) return NGX_AGAIN;
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");

		return NGX_HTTP_UPSTREAM_FT_INVALID_HEADER;
	}
}

static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc){
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "mytest_upstream_finalize_request");
}

static char *mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_http_core_loc_conf_t *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler = mytest_handler;

	return NGX_CONF_OK;
}



//TODO debug mytest_handler()
static ngx_int_t mytest_handler(ngx_http_request_t *r){
	//首先建立HTTP上下文结构体ngx_http_mytest_ctx_t
	mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
	if(myctx == NULL){
		myctx = ngx_pcalloc(r->pool, sizeof(mytest_ctx_t));
		if(myctx == NULL) return NGX_ERROR;
		//将新建的上下文与请求关联起来
		ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
	}

	//通过HTTP框架提供好的ngx_http_upstream_create()方法来创建upstream
	/*
	 * 对每一个要使用upstream的请求，必须调用且只能调用1次ngx_http_upstream_create()，它会初始化r->upstream成员
	 */
	if(ngx_http_upstream_create(r)!=NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
		return NGX_ERROR;
	}

	//得到配置结构体ngx_http_mytest_conf_t
	mytest_conf_t *mycf = (mytest_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
	ngx_http_upstream_t *u = r->upstream; //类型: ngx_http_upstream_t
	u->conf = &mycf->upstream; // ngx_http_upstream_conf_t

	//决定: 转发包体时使用的缓冲区
	//在mytest_create_loc_conf()中已指定为0
	u->buffering = mycf->upstream.buffering;


	u->resolved = (ngx_http_upstream_resolved_t *) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
	if(u->resolved == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pcalloc resolved error. %s", strerror(errno));
		return NGX_ERROR;
	}

	static struct sockaddr_in backendSockAddr;

	struct hostent *pHost = gethostbyname((char *)"www.baidu.com");
	if(pHost == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
		return NGX_ERROR;
	}

	//访问上游服务器的80端口
	backendSockAddr.sin_family = AF_INET;
	backendSockAddr.sin_port = htons((in_port_t)80);
	char *pDmsIP = inet_ntoa(*(struct in_addr *)(pHost->h_addr_list[0]));
	backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);

	//设置backendServer，存入"www.baidu.com"的IP地址字符串及长度
	myctx->backendServer.data = (u_char *)pDmsIP;
	myctx->backendServer.len = strlen(pDmsIP);

	//将地址设置到resolved成员中,该成员用于设置上游服务器的地址
	u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
	u->resolved->port = htons((in_port_t)80);
	u->resolved->socklen = sizeof(struct sockaddr_in);
	u->resolved->naddrs = 1;

	//设置3个必须实现的回调方法
	u->create_request = mytest_upstream_create_request;
	u->process_header = mytest_upstream_process_status_line;
	u->finalize_request = mytest_upstream_finalize_request;

	r->main->count++;

	//调用ngx_http_upstream_init()就是在启动upstream机制 书P161
	ngx_http_upstream_init(r);
	//必须返回NGX_DONE
	return NGX_DONE;
}