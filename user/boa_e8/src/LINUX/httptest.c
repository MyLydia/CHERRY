/* siyuan 2015-12-30 for yume HTTP test function */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "options.h"
#include "../defines.h"
#include "mib.h"
#include "utility.h"
#include "cJSON.h"
#include "httptest.h"

#include <ctype.h>
#include <pthread.h>

#ifdef CONFIG_HTTP_DOWNLOAD_TEST
#define TIME_INTERVAL 60 // 60s
struct timeval lastReqTime;

const char HTTPTESTCFGFILE[] = "/var/httptestcfg";
const char HTTPTESTRESULTFILE[] = "/var/httptestresult";

static HTTP_TEST_ENTRY testEntry;
static HTTP_TEST_RESULT testResult;
static int requestNum = 0;
static char downloadfile[MAX_URL_LEN];
static int httpTestEnable = 0;

struct downloadCfg downloadcfg[MAX_DOWNLOAD_THREAD];
int downloadwork[MAX_DOWNLOAD_THREAD];
int httpDownloadEnable = 0;

static int init_ssl(SSL_CTX ** ssl_ctx)
{
	SSL_METHOD *method;
	
	SSL_library_init();
	SSL_load_error_strings();
	method = (SSL_METHOD*)SSLv23_method();
	if(method == NULL) {
		printf("%s: SSLv23_method() failed\n",__func__);
		return -1;
	}
	*ssl_ctx = SSL_CTX_new(method);
	if(*ssl_ctx == NULL) {
		printf("%s: SSL_CTX_new() failed\n",__func__);
		return -1;
	}
	return 0;
}

static int free_ssl(SSL_CTX ** ssl_ctx)
{
	if(*ssl_ctx != NULL) {
		SSL_CTX_free(*ssl_ctx);
		*ssl_ctx = NULL;
	}
}

static void parseUrl(const char* url, char* web, char* file, int* port, int ishttp)    
{ 
    const char* pA; 
    const char* pB; 
	
    if(!url || !(*url))  
    {
        return; 
    }
	
    pA = url; 
    if(!strncmp(pA, "http://", 7))   
    {
        pA += 7;
    }
    else if(!strncmp(pA, "https://", 8))     
    {
        pA += 8;
    }
	
    pB = strchr(pA, '/'); 
    if(pB)     
    { 
        memcpy(web, pA, pB-pA);
		web[pB-pA] = 0; 
        if(*(pB+1))   
        { 
            memcpy(file, pB+1, strlen(pB)-1); 
            file[strlen(pB)-1] = 0; 
        } 
    } 
    else    
    {
        memcpy(web, pA, strlen(pA)); 
		web[strlen(pA)] = 0; 
    }
	
    pA = strchr(web, ':'); 
    if(pA)    
    {
        *port = atoi(pA + 1); 
    }
    else  
    {
		if(ishttp)
			*port = 80;
		else
			*port = 443;
    }
} 

static char *to_upper(char *str)
{
	char *start = str;

	while (*str) {		
		*str = toupper(*str);

		str++;
	}

	return start;
}

unsigned char HTTP_REQUEST[] =
{
	"%s /%s HTTP/1.1\r\n"
	"HOST: %s:%d\r\n"
	"%s"
	"\r\n"
};

static int buildHttpContent(char * request, HTTP_TEST_ENTRY * entry, char * host_addr, char * host_file, int port)
{
	char header[MAX_HEADER_LEN] = {0};
	cJSON * root;
	cJSON* temp;
	
	to_upper(entry->header);

	/* get header options from entry->header */
	root = cJSON_Parse(entry->header);
	if (!root) 
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return -1;
	}

	temp = cJSON_GetObjectItem(root, "CONTENT-TYPE");
	if(temp)
	{
		sprintf(header, "%s%s: %s\r\n", header, "CONTENT_TYPE", temp->valuestring);
	}

	temp = cJSON_GetObjectItem(root, "ACCEPT");
	if(temp)
	{
		sprintf(header, "%s%s: %s\r\n", header, "ACCEPT", temp->valuestring);
	}
	
	temp = cJSON_GetObjectItem(root, "CONNECTION");
	if(temp)
	{
		sprintf(header, "%s%s: %s\r\n", header, "CONNECTION", temp->valuestring);
	}

	sprintf(request, HTTP_REQUEST, (entry->reqType == M_GET) ? "GET" : "POST",
		    host_file, host_addr, port, header);
	return 1;
}

static int createConnection(char * host_addr, int port, int * fd)
{
	int sockfd = 0;
	struct sockaddr_in server_addr;
	struct hostent   *host;

	if((host = gethostbyname(host_addr)) == NULL)
    { 
        printf("Gethostname error, %s\n ", strerror(errno)); 
        return -1; 
    }

	if((sockfd=socket(AF_INET,SOCK_STREAM,0)) == -1)
    { 
        printf("Socket error:%s\a\n ", strerror(errno)); 
        return -1; 
    } 
 
    bzero(&server_addr,sizeof(server_addr)); 
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(port); 
    server_addr.sin_addr = *((struct in_addr*)host->h_addr); 
 
    if(connect(sockfd, (struct sockaddr*)(&server_addr), sizeof(struct sockaddr)) == -1)
    { 
        printf("Connect error:%s\n ", strerror(errno)); 
        return -1; 
    }

	*fd = sockfd;
	return 0;
}

static int processRequestAndReply(HTTP_TEST_RESULT * res, int ishttp, const char * data, char * host_addr, int port, SSL_CTX * ssl_ctx)
{
	int sockfd = 0;
	SSL * ssl;
	int r;
	struct  timeval    tv;
	char buff[512] = {0};
	int send = 0;
    int totalsend = 0; 
	int nbytes = 0;
	int first = 1;
	int ret = 0;

	if(createConnection(host_addr, port, &sockfd) < 0)
		return -1;

	if(ishttp == 0)
	{
		ssl = SSL_new(ssl_ctx);
		if(ssl == NULL) {
			printf("SSL_new() failed\n"); 
			ret = -1;
	        goto out;
		}

		if(!SSL_set_fd(ssl, sockfd)) {
			printf("SSL_set_fd() failed\n"); 
			ret = -1;
	        goto out;
		}

	    if ((r = SSL_connect(ssl)) <= 0) {
			int err = SSL_get_error(ssl, r);
	        if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
	        { 
	        	printf("SSL_connect() failed\n");
	        }
	        ret = -1;
	        goto out;
	    }
	}

	gettimeofday(&tv,NULL);
	sprintf(res->requestTime, "%u:%u", tv.tv_sec,tv.tv_usec);

	//printf("%s request:\n%s\n\n", ishttp?"http":"https", data);	
	send = 0;
	totalsend = 0; 
	nbytes = strlen(data); 
	while(totalsend < nbytes)  
	{ 
		if(ishttp)
			send = write(sockfd, data+totalsend, nbytes-totalsend);
		else
			send = SSL_write(ssl, data+totalsend, nbytes-totalsend);
		
	    if(send < 0)     
	    {
			if(ishttp)
				printf("write error!%s\n ", strerror(errno));
			else
				printf("SSL_write error!\n");

			ret = -1;
	        goto out;
	    } 
	    totalsend += send; 
	} 

	do{	
		if(ishttp)
			nbytes = read(sockfd,buff,512);
		else
			nbytes = SSL_read(ssl,buff,512);
		
	   	if(nbytes > 0)
		{ 
			if(first)
			{
				first = 0;
				sscanf(buff, "%*s %d", &res->code);
			}
			//printf("response:\n%s\n\n", buff);
				
			if(strstr(buff, "\r\n\r\n"))
				break;
		}
		else if(nbytes < 0)
		{
			if(ishttp)
				printf("read error!%s\n ", strerror(errno));
			else
				printf("SSL_read error!\n");

			ret = -1;
	        goto out;
		}
	}while(nbytes > 0);
	
	gettimeofday(&tv,NULL);
	sprintf(res->elapseTime, "%u:%u", tv.tv_sec,tv.tv_usec);

out:
	if(ishttp == 0 && ssl)
	{
		SSL_free(ssl);
		ssl = NULL;
	}
	close(sockfd);
	return ret;
}

static int doHttpRequest(HTTP_TEST_ENTRY * entry, HTTP_TEST_RESULT * res, SSL_CTX * ssl_ctx)
{
	struct  timeval    tv;
	int  port;
	char host_addr[128] = {0}; 
    char host_file[128] = {0}; 
	char sendbuff[512] = {0};
	int repeatNum = 0;
	int diff;
	
	memset((void*)res, 0, sizeof(HTTP_TEST_RESULT));
	
	parseUrl(entry->url, host_addr, host_file, &port, entry->isHttp);

	buildHttpContent(sendbuff, entry, host_addr, host_file,port);

	if(entry->repeat)
		repeatNum = entry->repeatNum;

	do{		
		gettimeofday(&tv,NULL);
		diff = tv.tv_sec - lastReqTime.tv_sec;
		if(diff < entry->interval)
		{
			sleep(entry->interval - diff);
		}
		gettimeofday(&lastReqTime,NULL);
		
		if(processRequestAndReply(res,entry->isHttp,sendbuff,host_addr,port,ssl_ctx) < 0)
			return -1;

		requestNum++;
		if(requestNum >= entry->freqNum)
			break;
	}while(repeatNum--);
	
	return 0;
}

/*
HttpTestItem object example
{
	"HttpTestItem":   {     
        	"ID": "ID",
        	"LinkType": "HTTP/HTTPS",
        	"URL": "URL",
        	"ReqType": "GET/POST",  
        	"HEADER":  "{\"Content-Type\": \"application/javascript\",\"Accept\": \"Text/css\",\"Cache-Control\": \"no-cache\"}",
        	"StartTime": "time",   
        	"EndTime": "time",   
        	"TimePeriod": "String",  
        	"Repeat_Ctrl": "True/False", 
        	"RepeatTimes": "String",  
        	"LagTime": "String",      
        	"Interval": "String",  
        	"Freq": "String"  
    }
}
*/
static int parseHttpTestConfig(char * data, HTTP_TEST_ENTRY * entry)
{
	cJSON * root;
	cJSON* item=NULL;
	cJSON* temp;
	
	root = cJSON_Parse(data);
	if (!root) 
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return -1;
	}

	item=cJSON_GetObjectItem(root,"HttpTestItem");
    if(!item)
    {
        goto error;
    }

	memset((void*)entry, 0, sizeof(HTTP_TEST_ENTRY));
	
	temp = cJSON_GetObjectItem(item, "ID");
	if(!temp) goto error;
    
	strcpy(entry->id, temp->valuestring);

	temp = cJSON_GetObjectItem(item, "LinkType");
	if(!temp) goto error;
	if(!strncmp(temp->valuestring, "HTTPS", 5))
		entry->isHttp = 0;
	else
		entry->isHttp = 1;

	temp = cJSON_GetObjectItem(item, "URL");
	if(!temp) goto error;
	strncpy(entry->url, temp->valuestring, MAX_URL_LEN);
	
	temp = cJSON_GetObjectItem(item, "ReqType");
	if(!temp) goto error;
	if(!strncmp(temp->valuestring, "GET", 3))
		entry->reqType = M_GET;
	else
		entry->reqType = M_POST;

	temp = cJSON_GetObjectItem(item, "HEADER");
	if(!temp) goto error;
	strncpy(entry->header, temp->valuestring, MAX_HEADER_LEN);

	temp = cJSON_GetObjectItem(item, "StartTime");
	if(!temp) goto error;
	strncpy(entry->startTime, temp->valuestring, MAX_TIME_LEN);

	temp = cJSON_GetObjectItem(item, "EndTime");
	if(!temp) goto error;
	strncpy(entry->endTime, temp->valuestring, MAX_TIME_LEN);
	
	temp = cJSON_GetObjectItem(item, "TimePeriod");
	if(!temp) goto error;
	entry->timePeriod = atoi(temp->valuestring);

	temp = cJSON_GetObjectItem(item, "Repeat_Ctrl");
	if(!temp) goto error;
	if(!strncmp(temp->valuestring, "True", 4))
		entry->repeat = 1;
	else
		entry->repeat = 0;

	temp = cJSON_GetObjectItem(item, "RepeatTimes");
	if(!temp) goto error;
	entry->repeatNum = atoi(temp->valuestring);

	temp = cJSON_GetObjectItem(item, "LagTime");
	if(!temp) goto error;
	entry->lagTime = atoi(temp->valuestring);

	temp = cJSON_GetObjectItem(item, "Interval");
	if(!temp) goto error;
	entry->interval = atoi(temp->valuestring);

	temp = cJSON_GetObjectItem(item, "Freq");
	if(!temp) goto error;
	entry->freqNum = atoi(temp->valuestring);

	cJSON_Delete(root);
	return 0;
	
error:
	cJSON_Delete(root);
	return -1;
}

static int getHttpTestConfig(char * filename, HTTP_TEST_ENTRY * entry)
{
	FILE *f;
	long len;
	char *data;	
	int ret;

	f=fopen(filename,"rb");
	if(!f)
		return -1;
	
	fseek(f,0,SEEK_END);
	len=ftell(f);
	fseek(f,0,SEEK_SET);
	
	data=(char*)malloc(len+1);
	if(!data)
		return -1;
	
	fread(data,1,len,f);
	fclose(f);
	
	ret = parseHttpTestConfig(data, entry);
	free(data);

	if(ret < 0)
		return -1;
	
	return 0;
}

static int check_should_request(time_t time, HTTP_TEST_ENTRY * entry)
{
	struct tm curTm;
	int startHour=0,startMinute=0, endHour=0, endMinute=0;
	int result = 0;
	int requestHour, requestMinute;
	struct  timeval    tv;
	
	memcpy(&curTm, localtime(&time), sizeof(curTm));
	
	if(requestNum >= entry->freqNum)
		return 0;

	gettimeofday(&tv,NULL);
	if(tv.tv_sec < (lastReqTime.tv_sec + entry->interval))
		return 0;

	sscanf(entry->startTime, "%d:%d", &startHour, &startMinute);
	sscanf(entry->endTime, "%d:%d", &endHour, &endMinute);
		
	if(startHour == endHour)
	{
		if((curTm.tm_hour == startHour) && (startMinute <= curTm.tm_min) && (endMinute > curTm.tm_min))
		{
			result = 1;
		}
	}
	else if((startHour <= curTm.tm_hour) && (endHour >= curTm.tm_hour))
	{
		if((startHour == curTm.tm_hour) && (startMinute <= curTm.tm_min))
		{
			result = 1;
		}
		else if((endHour == curTm.tm_hour) && (endMinute > curTm.tm_min))
		{
			result = 1;
		}
		else if((startHour < curTm.tm_hour) && (endHour > curTm.tm_hour))
		{
			result = 1;
		}
	}

	if(result)
	{
		/* FIXME : determine request time hour based on timePeriod
		     request time minute = lagTime value 
		*/
		if(entry->timePeriod > 0)
		{
			requestHour = startHour;
			while(curTm.tm_hour > requestHour)
				requestHour += entry->timePeriod;

			if(curTm.tm_hour != requestHour)
			{
			 	result = 0;
			}
			requestMinute = entry->lagTime / 60;
			if(curTm.tm_min != requestMinute)
				result = 0;
		}	
	}
	return result;
}

int saveHttpTestResult()
{
	cJSON *root, *result;
	char *out;
	HTTP_TEST_RESULT * res;
	char buf[200];
	FILE * fp;
	int finish = 0;
	
	if(requestNum >= testEntry.freqNum)
		finish = 1;

	res = &testResult;

	root = cJSON_CreateObject();
	if(root == NULL)
		return -1;
	
	cJSON_AddItemToObject(root, "RES_Result", result=cJSON_CreateObject());
	cJSON_AddNumberToObject(result,"Code", res->code);
	cJSON_AddStringToObject(result,"ElapseTime", res->elapseTime);
	cJSON_AddStringToObject(result,"Data", res->requestTime);
	cJSON_AddStringToObject(result,"result", res->cacheTime);

	out = cJSON_Print(root);
	if(out == NULL)
		return -1;
	cJSON_Delete(root);	
	strncpy(buf,out,200);	
	free(out);

	fp = fopen(HTTPTESTRESULTFILE,"w");
	if(fp)
	{
		fprintf(fp,"finish=%d\n",finish);
		fprintf(fp,"%s\n",buf);
		fclose(fp);
	}
	
	return 0;
}

/*return value: -2 http test not finish; -1 http test error; 0 test finish;*/
int getHttpTestResult(char * buf, int len)
{
	FILE * fp;
	char line[128];
	int finish = 0;
	int ret = -2;

	fp = fopen(HTTPTESTRESULTFILE,"r");
	if(fp)
	{	
		if(fgets(line, sizeof(line), fp) != NULL)
			sscanf(line, "finish=%d", &finish);
		else
			ret = -1;

		fread(buf, len, 1, fp);
		
		if(finish == 1)
			ret = 0;

		fclose(fp);
		unlink(HTTPTESTRESULTFILE);
	}
	else
		ret = -1;
	
	return ret;
}

void * httpTestThread(void *argu)
{	
	HTTP_TEST_RESULT res;

	if(testEntry.isHttp)
	{
		doHttpRequest(&testEntry, &res, NULL);
	}
	else
	{
		SSL_CTX * ssl_ctx;
		init_ssl(&ssl_ctx);
		doHttpRequest(&testEntry, &res, ssl_ctx);
		free_ssl(&ssl_ctx);
	}

	memcpy((void*)&testResult, &res, sizeof(HTTP_TEST_RESULT));
	saveHttpTestResult();

	return NULL;
}

void httpTestSchedule()
{
	time_t curTime;   
	pthread_t th;

	if(httpTestEnable == 0)
	{
		if(access(HTTPTESTCFGFILE,F_OK) < 0)
		{
			TIMEOUT(httpTestSchedule, 0, 1, httptest_ch);
		}
		else
		{
			if(getHttpTestConfig((char*)HTTPTESTCFGFILE, &testEntry) < 0)
				return;
			
			unlink(HTTPTESTCFGFILE);
			
			gettimeofday(&lastReqTime,NULL);
			lastReqTime.tv_sec -= testEntry.interval;
	
			requestNum = 0;
			httpTestEnable = 1;
			unlink(HTTPTESTRESULTFILE);
			
			TIMEOUT(httpTestSchedule, 0, TIME_INTERVAL, httptest_ch);
		}
	}
	else
	{
		/* restart test when there is a new config file */
		if(access(HTTPTESTCFGFILE,F_OK) == 0)
		{
			httpTestEnable = 0;
			TIMEOUT(httpTestSchedule, 0, 1, httptest_ch);
			return;
		}
		
		time(&curTime);

		if(check_should_request(curTime, &testEntry))
		{
			pthread_create(&th, NULL, &httpTestThread, NULL);
			pthread_detach(th);
		}

		if(requestNum < testEntry.freqNum)
		{
			TIMEOUT(httpTestSchedule, 0, TIME_INTERVAL, httptest_ch);
		}
		else
		{
			httpTestEnable = 0;
			TIMEOUT(httpTestSchedule, 0, 1, httptest_ch);
		}
	}
}

int httpRequestTest()
{
	if((access(downloadfile,F_OK)) < 0)
		return -1;
	
	if(rename(downloadfile,HTTPTESTCFGFILE) < 0)
		return -1;
	
	return 0;
}

/*return value: -1 download not finish; 0 test success; 1 test fail*/
int httpDownloadResultCheck()
{
	FILE *fp;
	int errcode;
	int i;
	
	for(i = 0; i < MAX_DOWNLOAD_THREAD; i++)
	{
		if(downloadwork[i])
			return -1;
	}

	httpDownloadEnable = 0;

	fp = fopen(HTPP_DOWNLOAD_RESULT_FILE, "r");

	if(fp)
	{
		fscanf(fp, "%d", &errcode);
		printf("%s fail errcode[%d]\n",__func__, errcode);
		
		fclose(fp);
		unlink(HTPP_DOWNLOAD_RESULT_FILE);		
		return 1;
	}
	//printf("%s success\n",__func__);

	return 0;
}

int getFileNameFromUrl(char * url, char * filename)
{
	char * p;
	char * tmp;

	/*example url: "ftp://192.168.1.42:80/test/httpcfg"*/
	if ( !strncmp(url, "ftp://", 6) )
	{
		p = url + 6;
	}
	else if( !strncmp(url, "http://", 7) )
	{
		p = url + 7;
	}
	else
		return -1;

	/* must have at least one "/" */
	if(strstr(p,"/") == NULL)
		return -1;
	
	while((tmp = strstr(p,"/")) != NULL)
	{
		p = tmp + 1;
	}

	strcpy(filename, p);
	return 0;
}

//return 0:OK, other:fail
static int call_cmd_with_timeout(const char *filename, int num, int time, ...)
{
	va_list ap;
	char *s;
	char *argv[24];
	int status=0, st, k;
	pid_t pid, wpid;
	struct  timeval    tv1, tv2;
	int timeout = 0;
	
    gettimeofday(&tv1,NULL);
	
	va_start(ap, time);
	
	for (k=0; k<num; k++)
	{
		s = va_arg(ap, char *);
		argv[k+1] = s;
	}

	argv[k+1] = NULL;
	if((pid = vfork()) == 0) {
		/* the child */
		char *env[3];

		signal(SIGINT, SIG_IGN);
		argv[0] = (char *)filename;
		env[0] = "PATH=/bin:/usr/bin:/etc:/sbin:/usr/sbin";
		env[1] = NULL;

		execve(filename, argv, env);

		printf("exec %s failed\n", filename);
		_exit(2);
	} else if(pid > 0) {
		{
			/* parent, wait till rc process dies before spawning 
			   or kill child when it is timeout*/
			while ((wpid = waitpid(pid,(int *) 0,WNOHANG)) != pid)
			{
				if (wpid == -1 && errno == ECHILD) { /* see wait(2) manpage */
					break;
				}

				gettimeofday(&tv2,NULL);
				if((tv1.tv_sec + time) < tv2.tv_sec)
				{
					timeout = 1;
					kill(pid, SIGTERM);
					break;
				}
				sleep(1);
			}
		}
	} else if(pid < 0) {
		printf("fork of %s failed\n", filename);
		status = -1;
	}
	if (wpid>0 && timeout == 0)
		if (WIFEXITED(st))
			status = WEXITSTATUS(st);
	va_end(ap);

	return status;
}

void * httpDownloadThread(void *argu)
{
	struct downloadCfg * cfg;
	int cfgIdx;
	char arguser[64];
	char argpasswd[64];
	char argpath[64];
	int i;
	int	errcode = 1;
	FILE *fp;
	char filename[64];
	
	cfgIdx = (intptr_t)argu;
	cfg = &downloadcfg[cfgIdx];
	snprintf(arguser, sizeof(arguser), "user=%s", cfg->user);
	snprintf(argpasswd, sizeof(argpasswd), "passwd=%s", cfg->passwd);
	snprintf(argpath, sizeof(argpath), "path=%s", DOWNLOAD_PATH);

	for(i = 0; i < cfg->num; i++)
	{
		memset(filename, 0, sizeof(filename));
		if(getFileNameFromUrl(cfg->url[i], filename) < 0)
			continue;
		
		sprintf(downloadfile,"%s/%s", DOWNLOAD_PATH, filename);
		unlink(downloadfile); /*unlink old existing file */
		
		if(cfg->time == 0)
			errcode = call_cmd("/bin/wget_manage", 5, 1, arguser, argpasswd, argpath, cfg->url[i], "port=21");
		else
			errcode = call_cmd_with_timeout("/bin/wget_manage", 5, cfg->time, arguser, argpasswd, argpath, cfg->url[i], "port=21");
		if(errcode)
		{
			fp = fopen(HTPP_DOWNLOAD_RESULT_FILE, "w");
			if(fp)
			{
				fprintf(fp, "%d\n", errcode);
				fclose(fp);
			}
			printf("%s errcode[%d] url[%s]\n",__func__, errcode,cfg->url[i]);
		}
	}

	downloadwork[cfgIdx] = 0;
	return NULL;
}

/*return value: -1 set fail; 0 set success*/
int httpDownloadTest(char * user, char * passwd, char * url)
{
	pthread_t th[MAX_DOWNLOAD_THREAD];
	int thNum;
	int urlNum = 0;
	int perThNum = 1, oneLargeIdx = 0; /*set url num for each thread to download*/
	int i, j, urlIdx;
	char * ptr, *p;
	char urls[MAX_URL_NUM][MAX_URL_LEN] = {{0}};

	//url example: "ftp://192.168.1.42/test1.txt|ftp://192.168.1.42/test2.txt"
	p = ptr = url;

	while(*p != '\0')
	{
		if(*p == '|')
		{
			if((urlNum+1) >= MAX_URL_NUM)
				break;
			
			strncpy(urls[urlNum++], ptr, p-ptr);
			ptr = p+1;
			p = ptr;
		}
		else
		{
			p++;
		}
	}
	strncpy(urls[urlNum++], ptr, p-ptr);
	
	thNum = (urlNum <= MAX_DOWNLOAD_THREAD) ? urlNum : MAX_DOWNLOAD_THREAD; 
	memset(downloadwork, 0 , sizeof(downloadwork));
	for(i = 0; i < thNum; i++)
	{
		downloadwork[i] = 1;
	}
	
	if(urlNum > MAX_DOWNLOAD_THREAD)
	{
		perThNum = urlNum / MAX_DOWNLOAD_THREAD;
		oneLargeIdx = urlNum % MAX_DOWNLOAD_THREAD;
	}

	urlIdx = 0;
	for(i = 0; i < thNum; i++)
	{
		memset((void*)&downloadcfg[i], 0, sizeof(struct downloadCfg));
		strncpy(downloadcfg[i].user, user, 64);
		strncpy(downloadcfg[i].passwd, passwd, 64);	

		if(i < oneLargeIdx)
			downloadcfg[i].num = perThNum+1;
		else
			downloadcfg[i].num = perThNum;

		for(j = 0; j < downloadcfg[i].num; j++)
		{
			strncpy(downloadcfg[i].url[j], urls[urlIdx++], MAX_URL_LEN);	
		}
		
		pthread_create(&th[i], NULL, &httpDownloadThread, (void*)(intptr_t)i);
		pthread_detach(th[i]);
	}

	httpDownloadEnable = 1;

	return 0;
}

/* return value: Size of file, in kbytes. */
static unsigned int get_file_size(const char *path)  
{  
    unsigned int filesize = 0;      
    struct stat statbuff;  
    if(stat(path, &statbuff) < 0){  
        return filesize;  
    }else{  
        filesize = statbuff.st_size >> 10;  
    }  
    return filesize;  
}

/* time: kill all threads after testing time seconds
   return value: -1 set fail; 0 set success*/
int httpDownloadTestWithTime(int time, char * user, char * passwd, char * url, unsigned int * result)
{
	pthread_t th[MAX_DOWNLOAD_THREAD];
	int thNum;
	int urlNum = 0;
	int perThNum = 1, oneLargeIdx = 0; /*set url num for each thread to download*/
	int i, j, urlIdx;
	char * ptr, *p;
	char urls[MAX_URL_NUM][MAX_URL_LEN] = {{0}};
	unsigned int downloadSize = 0;
	
	//url example: "ftp://192.168.1.42/test1.txt|ftp://192.168.1.42/test2.txt"
	p = ptr = url;

	while(*p != '\0')
	{
		if(*p == '|')
		{
			if((urlNum+1) >= MAX_URL_NUM)
				break;
			
			strncpy(urls[urlNum++], ptr, p-ptr);
			ptr = p+1;
			p = ptr;
		}
		else
		{
			p++;
		}
	}
	strncpy(urls[urlNum++], ptr, p-ptr);
	
	thNum = (urlNum <= MAX_DOWNLOAD_THREAD) ? urlNum : MAX_DOWNLOAD_THREAD; 
	memset(downloadwork, 0 , sizeof(downloadwork));
	for(i = 0; i < thNum; i++)
	{
		downloadwork[i] = 1;
	}
	
	if(urlNum > MAX_DOWNLOAD_THREAD)
	{
		perThNum = urlNum / MAX_DOWNLOAD_THREAD;
		oneLargeIdx = urlNum % MAX_DOWNLOAD_THREAD;
	}

	urlIdx = 0;
	for(i = 0; i < thNum; i++)
	{
		memset((void*)&downloadcfg[i], 0, sizeof(struct downloadCfg));
		strncpy(downloadcfg[i].user, user, 64);
		strncpy(downloadcfg[i].passwd, passwd, 64);	
		downloadcfg[i].time = time;
		
		if(i < oneLargeIdx)
			downloadcfg[i].num = perThNum+1;
		else
			downloadcfg[i].num = perThNum;

		for(j = 0; j < downloadcfg[i].num; j++)
		{
			strncpy(downloadcfg[i].url[j], urls[urlIdx++], MAX_URL_LEN);	
		}
		
		pthread_create(&th[i], NULL, &httpDownloadThread, (void*)(intptr_t)i);
	}

	for(i = 0; i < thNum; i++)
	{
		pthread_join(th[i], NULL);
	}
	
	httpDownloadEnable = 1;

	for(i = 0; i < thNum; i++)
	{
		char filename[64];
		int size;
		for(j = 0; j < downloadcfg[i].num; j++)
		{
			memset(filename, 0, sizeof(filename));
			if(getFileNameFromUrl(downloadcfg[i].url[j], filename) < 0)
				continue;
			sprintf(downloadfile,"%s/%s", DOWNLOAD_PATH, filename);

			if((size = get_file_size(downloadfile)) > 0)
			{
				downloadSize += size;
			}
		}
	}

	*result = downloadSize;
	return 0;

}
#endif
