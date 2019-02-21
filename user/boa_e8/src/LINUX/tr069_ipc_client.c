#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#define TR069_LISTENER_FILE "/tmp/tr069_listener.sock"
#define MAX_TR069_IPC_BUF 2048

enum tr069_cmd
{
	TR069_CMD_GET_NAME = 1,
	TR069_CMD_GET_VALUE,
	TR069_CMD_SET_VALUE,
	TR069_CMD_ADD_OBJECT,
	TR069_CMD_DEL_OBJECT,
	TR069_CMD_MAX
};

struct tr069_ipc_msg
{
	unsigned int cmd;
	char name[256];
	char value[256];
};

struct tr069_ParameterValueStruct
{
	char Name[256];
	int type;
	char Value[256];
};

struct tr069_ParameterNameStruct
{
	char Name[256];
	int writable;
};

struct tr069_FaultStruct
{
	unsigned int FaultCode;
	char FaultString[128];
};

struct tr069_AddObjectResponse
{
	unsigned int InstanceNumber;
};

struct tr069_ResultHeaderStruct
{
	int data_len;
	int status;
};


int tr069_client_GetParameter(unsigned int cmd, char *name, char **pResult)
{
	char buf[520] = {0};
	struct tr069_ipc_msg *msg = NULL;
	int connect_fd = 0;
	int count = 0;
	char result_buf[MAX_TR069_IPC_BUF] = {0};
	static struct sockaddr_un srv_addr;

	msg = (struct tr069_ipc_msg *)buf;
	msg->cmd = cmd;
	strncpy(msg->name, name, strlen(name));

	connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (connect_fd < 0)
	{
		printf("tr069_client_GetParameter: cannot create communication socket\n");
		return -1;
	}
	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, TR069_LISTENER_FILE);

	if (connect(connect_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) == -1)
	{
		printf("tr069_client_GetParameter: cannot connect to the server\n");
		close(connect_fd);
		return -1;
	}

	if (send(connect_fd, (char *)msg, sizeof(struct tr069_ipc_msg), 0) == -1)
	{
		printf("tr069_client_GetParameter: send failed\n");
		close(connect_fd);
		return -1;
	}

	int done = 0;
	int result_data_len = 0;
	char *pTmp = NULL;
	struct tr069_ResultHeaderStruct *result_msg = NULL;

	while (1)
	{
		count = recv(connect_fd, result_buf, sizeof(result_buf), 0);
		//printf("count = %d\n", count);
		if (count == -1)
		{
			printf("tr069_client_GetParameter: recv failed\n");
			close(connect_fd);
			return -1;
		}
		else if (count == 0)
		{
			done = 1;
			break;
		}
		else if (count > 0)
		{
			if (result_data_len == 0)
			{
				result_msg = (struct tr069_ResultHeaderStruct *)result_buf;
				result_data_len = result_msg->data_len;
				*pResult = malloc(sizeof(struct tr069_ResultHeaderStruct) + result_data_len);
				pTmp = *pResult;
			}
			memcpy(pTmp, result_buf, count);
			pTmp += count;
		}
	}

	close(connect_fd);

	//printf("done = %d\n", done);
	//printf("(pTmp - *pResult) = %d\n", (pTmp - *pResult));
	//printf("result_data_len = %d\n", result_data_len);
	if (done && ((pTmp - *pResult) == (result_data_len + sizeof(struct tr069_ResultHeaderStruct)))) {
		//printf("OK\n");
		return 0;
	}
	else {
		//printf("FAIL\n");
		return -1;
	}
}

int tr069_client_SetParameter(unsigned int cmd, char *name, char *value, char **pResult)
{
	char buf[520] = {0};
	struct tr069_ipc_msg *msg = NULL;
	int connect_fd = 0;
	int count = 0;
	char result_buf[MAX_TR069_IPC_BUF] = {0};
	static struct sockaddr_un srv_addr;

	msg = (struct tr069_ipc_msg *)buf;
	msg->cmd = cmd;
	strncpy(msg->name, name, strlen(name));
	strncpy(msg->value, value, strlen(value));

	connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (connect_fd < 0)
	{
		printf("tr069_client_SetParameter: cannot create communication socket\n");
		return -1;
	}
	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, TR069_LISTENER_FILE);

	if (connect(connect_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) == -1)
	{
		printf("tr069_client_SetParameter: cannot connect to the server\n");
		close(connect_fd);
		return -1;
	}

	if (send(connect_fd, (char *)msg, sizeof(struct tr069_ipc_msg), 0) == -1)
	{
		printf("tr069_client_SetParameter: send failed\n");
		close(connect_fd);
		return -1;
	}

	int done = 0;
	int result_data_len = 0;
	char *pTmp = NULL;
	struct tr069_ResultHeaderStruct *result_msg = NULL;

	while (1)
	{
		count = recv(connect_fd, result_buf, sizeof(result_buf), 0);
		//printf("count = %d\n", count);
		if (count == -1)
		{
			printf("tr069_client_SetParameter: recv failed\n");
			close(connect_fd);
			return -1;
		}
		else if (count == 0)
		{
			done = 1;
			break;
		}
		else if (count > 0)
		{
			if (result_data_len == 0)
			{
				result_msg = (struct tr069_ResultHeaderStruct *)result_buf;
				result_data_len = result_msg->data_len;
				*pResult = malloc(sizeof(struct tr069_ResultHeaderStruct) + result_data_len);
				pTmp = *pResult;
			}
			memcpy(pTmp, result_buf, count);
			pTmp += count;
		}
	}

	close(connect_fd);

	//printf("done = %d\n", done);
	//printf("(pTmp - *pResult) = %d\n", (pTmp - *pResult));
	//printf("result_data_len = %d\n", result_data_len);
	if (done && ((pTmp - *pResult) == (result_data_len + sizeof(struct tr069_ResultHeaderStruct)))) {
		//printf("OK\n");
		return 0;
	}
	else {
		//printf("FAIL\n");
		return -1;
	}
}

void show_GetParameterNameResult(char *pResult)
{
	int i = 0, result_data_len = 0;
	struct tr069_ResultHeaderStruct *result_msg = NULL;
	struct tr069_ParameterNameStruct *pn = NULL;

	if (pResult == NULL)
	{
		return;
	}

	result_msg = (struct tr069_ResultHeaderStruct *)pResult;
	result_data_len = result_msg->data_len;
	//printf("result_data_len = %d\n", result_data_len);

	for (i = 0; i < (result_data_len / sizeof(struct tr069_ParameterNameStruct)); i++)
	{
		pn = (struct tr069_ParameterNameStruct *)(pResult + sizeof(struct tr069_ResultHeaderStruct) + (sizeof(struct tr069_ParameterNameStruct) * i));
		printf("[%d] pn->Name = %s, pn->writable = %d\n", i, pn->Name, pn->writable);
	}
}

void show_GetParameterValueResult(char *pResult)
{
	int i = 0, result_data_len = 0;
	struct tr069_ResultHeaderStruct *result_msg = NULL;
	struct tr069_ParameterValueStruct *pv = NULL;

	if (pResult == NULL)
	{
		return;
	}

	result_msg = (struct tr069_ResultHeaderStruct *)pResult;
	result_data_len = result_msg->data_len;
	//printf("result_data_len = %d\n", result_data_len);

	for (i = 0; i < (result_data_len / sizeof(struct tr069_ParameterValueStruct)); i++)
	{
		pv = (struct tr069_ParameterValueStruct *)(pResult + sizeof(struct tr069_ResultHeaderStruct) + (sizeof(struct tr069_ParameterValueStruct) * i));
		printf("[%d] pv->Name = %s, pv->type = %d, pv->Value = %s\n", i, pv->Name, pv->type, pv->Value);
	}
}

void show_AddObjectResult(char *pResult)
{
	struct tr069_ResultHeaderStruct *result_msg = NULL;

	if (pResult == NULL)
	{
		return;
	}

	result_msg = (struct tr069_ResultHeaderStruct *)pResult;
	//printf("result_msg->data_len = %d\n", result_msg->data_len);

	if (result_msg->status < 0)
	{
		struct tr069_FaultStruct *fs = NULL;

		fs = (struct tr069_FaultStruct *)(pResult + sizeof(struct tr069_ResultHeaderStruct));
		printf("[status = %d] fs->FaultCode = %d, fs->FaultString = %s\n", result_msg->status, fs->FaultCode, fs->FaultString);
	}
	else
	{
		struct tr069_AddObjectResponse *ao = NULL;

		ao = (struct tr069_AddObjectResponse *)(pResult + sizeof(struct tr069_ResultHeaderStruct));
		printf("[status = %d] ao->InstanceNumber = %d\n", result_msg->status, ao->InstanceNumber);
	}
}

void show_DeleteObjectResult(char *pResult)
{
	struct tr069_ResultHeaderStruct *result_msg = NULL;

	if (pResult == NULL)
	{
		return;
	}

	result_msg = (struct tr069_ResultHeaderStruct *)pResult;
	//printf("result_msg->data_len = %d\n", result_msg->data_len);

	if (result_msg->status < 0)
	{
		struct tr069_FaultStruct *fs = NULL;

		fs = (struct tr069_FaultStruct *)(pResult + sizeof(struct tr069_ResultHeaderStruct));
		printf("[status = %d] fs->FaultCode = %d, fs->FaultString = %s\n", result_msg->status, fs->FaultCode, fs->FaultString);
	}
	else
	{
		printf("[status = %d]\n", result_msg->status);
	}
}

int main(int argc, char **argv)
{
	if(argc >= 2)
	{
		int i = 0;
		for (i = 1 ; i < argc; i++)
		{
			if (strcmp(argv[i], "-gn") == 0)
			{
				char *pResult = NULL;
				char **tmp = &pResult;
				if (tr069_client_GetParameter(TR069_CMD_GET_NAME, argv[i+1], tmp) == 0)
				{
					show_GetParameterNameResult(pResult);
				}

				if (*tmp) {
					free(*tmp);
				}
			}
			else if (strcmp(argv[i], "-gv") == 0)
			{
				char *pResult = NULL;
				char **tmp = &pResult;
				if (tr069_client_GetParameter(TR069_CMD_GET_VALUE, argv[i+1], tmp) == 0)
				{
					show_GetParameterValueResult(pResult);
				}

				if (*tmp) {
					free(*tmp);
				}
			}
			else if (strcmp(argv[i], "-sv") == 0)
			{
				char *pResult = NULL;
				char **tmp = &pResult;
				if (tr069_client_SetParameter(TR069_CMD_SET_VALUE, argv[i+1], argv[i+2], tmp) == 0)
				{
					//show_GetParameterValueResult(pResult);
				}

				if (*tmp) {
					free(*tmp);
				}
			}
			else if (strcmp(argv[i], "-ao") == 0)
			{
				char *pResult = NULL;
				char **tmp = &pResult;
				if (tr069_client_GetParameter(TR069_CMD_ADD_OBJECT, argv[i+1], tmp) == 0)
				{
					show_AddObjectResult(pResult);
				}

				if (*tmp) {
					free(*tmp);
				}
			}
			else if (strcmp(argv[i], "-do") == 0)
			{
				char *pResult = NULL;
				char **tmp = &pResult;
				if (tr069_client_GetParameter(TR069_CMD_DEL_OBJECT, argv[i+1], tmp) == 0)
				{
					show_DeleteObjectResult(pResult);
				}

				if (*tmp) {
					free(*tmp);
				}
			}
		}
	}

	return 0;
}

