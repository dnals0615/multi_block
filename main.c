#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pcap.h>

//unsigned char *target;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	unsigned char *host = "Host: ";
	unsigned char host_name[200] = {0,};
	int host_name_len = 0;
	int check;
	int count = 0 ;	
	int i = 0;
	char buf[200];
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	
	nfq_get_payload(nfa, (unsigned char **)&data);
	
	unsigned char * tmp = (unsigned char *)data;

	if(tmp[9] != 6) return 0; // check TCP

	//printf("ip protocol : %d\n", tmp[9]); //check!!!!!!

	int iplen = (tmp[0]&0x0f) * 4;
	
	//printf("iplen : %d\n", iplen); //check!!!!!!
	
	//printf("tmp[iplen] : %d\n", tmp[iplen]);  //check!!!!
	tmp += iplen; //tmp[0] = tcp start
	//printf("tmp[0] : %d\n", tmp[0]);   // check!!!
	int tcplen = (tmp[12]>>4) * 4;
	//printf("tcplen : %d\n", tcplen);   //check!!!!
	
	//printf("tmp[tcplen] : %d\n", tmp[tcplen]);  //check!!!!!!
	tmp += tcplen;
	//printf("tmp[0] : %d\n",tmp[0]);
	
	unsigned char * http = (unsigned char *)tmp;

	//printf("http[0] : %d  ?  tmp[0] : %d\n", http[0],tmp[0]);	//check !!!!!
	printf("여기까지는 오케이\n");
	for(i = 0; i<1000;i++){
		if(strncmp(http, host, 6) == 0  ) break;
		else http++;
	}
	printf("%d\n", i);
	if(i==1000) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	http += 6;          // 여기서 부터 호스트 이름 가리킴, 0x0d,0x0a 나올때 까지 저장하기  
	printf("good!\n"); //
	
	//host_name[0] = http[0];
	//printf("%c,%c\n", host_name[0], http[0] );
	
	//host_name = "\0"; 

	for(count=0;count<200;count++){
		if(http[count] == 0x0d)
			break;
		else host_name[count] = http[count];
	} // 여기까지 하면 host_name 에 이름 저장됨. 이제 파일에서 이 이름이 있나 검색하기.
	if(count == 200) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); //
	printf("심지어 여기도 오케이\n");

	printf("%s\n", host_name);  //check
	sprintf(buf, "grep -w %s sorted_list.csv", host_name);
	check = system(buf);
	
	if(check == 0)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	
//	printf("http : %c%c%c%c\n", http[0],http[1], http[2], http[3]);
//	printf("host : %s\n", target);
// 	printf("비교값 : %d\n\n",strncmp(tmp, target, strlen(target)));
	
	/*if(strncmp(http, target, strlen(target)) == 0)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);*/

}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	system("iptables -A OUTPUT -p tcp -j NFQUEUE");

	//target = argv[1];

	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
