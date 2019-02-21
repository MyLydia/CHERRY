
/*
 *	msgutil.c -- System V IPC message queue utility
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include "msgq.h"

int open_queue( key_t keyval, int flag )
{
	int     qid;

	if (flag == MQ_CREATE) {
		/* Create the queue - fail if exists */
		if((qid = msgget( keyval, IPC_CREAT |IPC_EXCL | 0660 )) == -1)
		{
			return(-1);
		}
	}
	else {
		/* Get the queue id - fail if not exists */
		if((qid = msgget( keyval, 0660 )) == -1)
		{
			return(-1);
		}
	}

	return(qid);
}

const char* get_process_name_by_pid(const int pid, char *name, int name_length)
{
	if(name){
		sprintf(name, "/proc/%d/cmdline",pid);
		FILE* f = fopen(name,"r");
		if(f){
			size_t size;
			size = fread(name, sizeof(char), name_length, f);
			if(size>0){
				if('\n'==name[size-1])
					name[size-1]='\0';
			}
			fclose(f);
		} else {
			name[0] = '\0';
		}
		name[name_length-1] = '\0';
	}
	return name;
}

static void drop_one_message(int qid, long type)
{
	char process_name[513];
	struct mymsgbuf qbuf;

	printf("[CONFIGD] Try clean one message!\n");

	if ((msgrcv(qid, (struct msgbuf *)&qbuf,
		sizeof(struct mymsgbuf)-sizeof(long), type, MSG_EXCEPT)) < 0) {
		perror("msq clean up");
		printf("[CONFIGD] Try clean one message! ERROR\n");
	} else {
		printf("[CONFIGD] Clean one message! request %s pid %ld, \n\ttgid %s pid %ld\n\tmtype %ld\n",
				get_process_name_by_pid(qbuf.request, process_name, sizeof(process_name)), qbuf.request,
				get_process_name_by_pid(qbuf.tgid, process_name, sizeof(process_name)), qbuf.tgid,
				qbuf.mtype);
		printf("[CONFIGD] cmd=%d, arg1=%d, arg2=%d\n", qbuf.msg.cmd, qbuf.msg.arg1, qbuf.msg.arg1);
	}
	return;
}



void send_message_nonblock(int qid, long type, long req, long tgid, MSG_T *msg)
{
	struct mymsgbuf qbuf;
	long time_start;
	struct sysinfo systeminfo;
	int showmsg=0;

	/* Send a message to the queue */
	//printf("Sending a message ... qid=%d, mtype=%d\n", qid, type);
	qbuf.mtype = type;
	qbuf.request = req;
	qbuf.tgid = tgid;
	qbuf.msg.cmd = msg->cmd;
	qbuf.msg.arg1 = msg->arg1;
	qbuf.msg.arg2 = msg->arg2;
	memcpy(qbuf.msg.mtext, msg->mtext, MAX_SEND_SIZE);

	sysinfo(&systeminfo);
	time_start=systeminfo.uptime;
callmsgsnd:
	if((msgsnd(qid, &qbuf, sizeof(struct mymsgbuf)-sizeof(long), IPC_NOWAIT)) == -1)
	{
		if(errno==EAGAIN)
		{
			sysinfo(&systeminfo);
			//if( (showmsg==0)&&(systeminfo.uptime-time_start>120) )
			if( systeminfo.uptime-time_start>10 )
			{
				fprintf( stderr, "\nsend_message_nonblock: call msgsnd timeout and errno==EAGAIN reqid==%d\n", req );
				//showmsg=1;
				time_start = systeminfo.uptime;
				drop_one_message(qid, type);
			}
			goto callmsgsnd;
		}else{
			perror("msgsnd");
			exit(1);
		}
	}

	return;
}

void send_message(int qid, long type, long req, long tgid, MSG_T *msg)
{
	struct mymsgbuf qbuf;

	/* Send a message to the queue */
	//printf("Sending a message ... qid=%d, mtype=%d\n", qid, type);
	qbuf.mtype = type;
	qbuf.request = req;
	qbuf.tgid = tgid;
	qbuf.msg.cmd = msg->cmd;
	qbuf.msg.arg1 = msg->arg1;
	qbuf.msg.arg2 = msg->arg2;
	memcpy(qbuf.msg.mtext, msg->mtext, MAX_SEND_SIZE);

	if((msgsnd(qid, &qbuf, sizeof(struct mymsgbuf)-sizeof(long), 0)) == -1)
	{
		perror("msgsnd");
		exit(1);
	}
	return;
}

/*
	Return Value:
	Return -1 on failure;
	otherwise return the number of bytes actually copied into the mtext array.
*/
int read_message(int qid, struct mymsgbuf *qbuf, long type)
{
	int ret;

	/* Read a message from the queue */
	//printf("Reading a message ...\n");
	qbuf->mtype = type;

read_retry:
	ret=msgrcv(qid, (struct msgbuf *)qbuf,
		sizeof(struct mymsgbuf)-sizeof(long), type, 0);
	if (ret == -1 && errno == EINTR) {
		//printf("EINTR\n");
		goto read_retry;
	}
/*
	if (ret == -1) {
		switch (errno) {
			case E2BIG   :
				printf("E2BIG    \n");
				break;
			case EACCES :
				printf("EACCES  \n");
				break;
			case EFAULT   :
				printf("EFAULT   \n");
				break;
			case EIDRM  :
				printf("EIDRM  \n");
				break;
			case EINTR    :
				printf("EINTR    \n");
				break;
			case EINVAL   :
				printf("EINVAL   \n");
				break;
			case ENOMSG   :
				printf("ENOMSG   \n");
				break;
			default:
				printf("unknown\n");
		}
	}
	printf("Type: %ld Text: %s\n", qbuf->mtype, qbuf->mtext);
*/
	return ret;
}

void remove_queue(int qid)
{
	/* Remove the queue */
	msgctl(qid, IPC_RMID, 0);
}

/*
 *	Set max number of bytes allowed in queue (msg_qbytes).
 *	/proc/sys/kernel/msgmnb		default max size of a message queue.
 *	/proc/sys/kernel/msgmax		max size of a message (bytes).
 */
int set_msgqueue_max_size(int qid, unsigned int msgmaxsize)
{
	int ret=-1;
	struct msqid_ds msgqidds;

	//fprintf(stderr, "%s:%d>qid=%d, msgmaxsize=%d\n", __FUNCTION__, __LINE__, qid, msgmaxsize);
	if( msgctl(qid, IPC_STAT, &msgqidds)==0 )
	{
		msgqidds.msg_qbytes = msgmaxsize;
		if( msgctl(qid, IPC_SET, &msgqidds)==0 )
			ret=0;
		else
			perror( "msgctl,IPC_SET" );

		if( (msgctl(qid, IPC_STAT, &msgqidds)==0) &&(msgqidds.msg_qbytes == msgmaxsize) )
				fprintf(stderr, "%s:%d> set msgqidds.msg_qbytes=%d OK\n", __FUNCTION__, __LINE__, msgmaxsize);
	}else
		perror( "msgctl,IPC_STAT" );

	return ret;
}


