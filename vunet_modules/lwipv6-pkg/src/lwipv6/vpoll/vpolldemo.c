#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <vpoll.h>

#define CHILDSTACKSIZE 4096

struct child_data {
	int fd;
};

static void *child(void *arg) {
  struct child_data *data = arg;
	sleep(3);
	vpoll_ctl(data->fd, VPOLL_CTL_ADDEVENTS,  EPOLLIN);
	sleep(3);
	vpoll_ctl(data->fd, VPOLL_CTL_ADDEVENTS,  EPOLLIN);
	sleep(3);
	vpoll_ctl(data->fd, VPOLL_CTL_ADDEVENTS,  EPOLLOUT);
	sleep(3);
	vpoll_ctl(data->fd, VPOLL_CTL_ADDEVENTS,  EPOLLHUP);
	sleep(3);
	return NULL;
}

int main(int argc, char *argv[]) {
	struct child_data data;
	int vpollfd = vpoll_create(0, FD_CLOEXEC);
	data.fd = vpollfd;

	pthread_t t;
  pthread_create(&t, NULL, child, &data);

	int epfd = epoll_create1(EPOLL_CLOEXEC);
  struct epoll_event reqevents={EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLOUT | EPOLLHUP | EPOLLPRI};
  epoll_ctl(epfd,  EPOLL_CTL_ADD, vpollfd, &reqevents);

	while (1) {
		struct epoll_event ev;
		int n = epoll_wait(epfd, &ev, 1, 1000);
		if (n < 0) {
			perror("epoll_wait");
			break;
		}
		if (n > 0) {
			printf("GOT event %x\n", ev.events);
			vpoll_ctl(vpollfd, VPOLL_CTL_DELEVENTS, ev.events);
			if (ev.events & EPOLLHUP)
        break;
		} else {
			printf("timeout\n");
		}
	}
	vpoll_close(vpollfd);
	close(epfd);
	return 0;
}
