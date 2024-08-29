/*   OWASP NINJA PingU: Is Not Just a Ping Utility
 *
 *   Copyright (C) 2014 Guifre Ruiz <guifre.ruiz@owasp.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/timerfd.h>

#include "socks.c"
#include "pluginHandler.c"

#define BUFFER_SIZE 512
#define MESSAGE_SIZE 5000
#define EPOLL_MAX_EVENTS 10

pthread_mutex_t mutex_epfd = PTHREAD_MUTEX_INITIALIZER;
int epfd;

void initialize_connector(struct agentInfo *aInfo);
void handle_write_event(int fd);
void handle_read_event(int fd);

int* start_connector(void *agentI) {
	struct agentInfo *aInfo = agentI;
    initialize_connector(aInfo);
    static struct epoll_event *events;
	if (NULL == (events = calloc(MAX_SOCKS, sizeof(struct epoll_event)))) {
		perror("calloc events");
		exit(1);
	};

    while (!endOfScan) {
        int event_count = epoll_wait(epfd, events, EPOLL_MAX_EVENTS, -1);
        for (int i = 0; i < event_count; i++)
            if (events[i].events & (EPOLLERR | EPOLLRDHUP | EPOLLHUP))
				deleteSock(epfd, events[i].data.fd);
            else if (events[i].events & EPOLLOUT)
                handle_write_event(events[i].data.fd);
            else if (events[i].events & EPOLLIN)
                handle_read_event(events[i].data.fd);
    }

    onStopPlugin();
    pthread_mutex_destroy(&mutex_epfd);
    close(epfd);
    return 0;
}


void handle_write_event(int fd) {
    if (socket_check(fd) != 0) {
        deleteSock(epfd, fd);
        return;
    }

    int port = (int)getPortBySock(fd);
    char *message = malloc(sizeof(char) * 80);

    if (message == NULL) {
        perror("Failed to allocate memory for message");
        return;
    }

    getServiceInput(port, message);
    int message_length = strlen(message);

    if (send(fd, message, message_length, 0) < 0) {
        free(message);
        return;
    }

    struct epoll_event event_mask;
    event_mask.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
    event_mask.data.fd = fd;

    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event_mask) != 0) {
        deleteSock(epfd, fd);
    }

    free(message);
}

void handle_read_event(int fd) {
    if (socket_check(fd) != 0) {
        deleteSock(epfd, fd);
        return;
    }

    struct host hostInfo;
    hostInfo.port = (int)getPortBySock(fd);
    hostInfo.ip = getHostBySock(fd);

    if (hostInfo.port == -1 || strlen(hostInfo.ip) == 0) {
        deleteSock(epfd, fd);
        return;
    }

    char buffer[BUFFER_SIZE];
    memset(buffer, 0x0, BUFFER_SIZE);
    char *msg = malloc(MESSAGE_SIZE);

    if (msg == NULL) {
        perror("Failed to allocate memory for msg");
        deleteSock(epfd, fd);
        return;
    }

    int total_data = 0, data_count = 0;

    while ((data_count = recv(fd, buffer, BUFFER_SIZE, 0)) > 0) {
        if (total_data + data_count > MESSAGE_SIZE - 1) break;

        if (total_data == 0) strncpy(msg, buffer, MESSAGE_SIZE - 1);
        else strncat(msg, buffer, MESSAGE_SIZE - 1 - total_data);

        total_data += data_count;
    }

    if (total_data > 0) {
        persistAck(hostInfo.ip, hostInfo.port, msg);
        provideOutput(hostInfo.ip, hostInfo.port, msg);
    }

    free(msg);
    deleteSock(epfd, fd);
}
