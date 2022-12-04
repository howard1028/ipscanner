#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <net/if.h>

#include "fill_packet.h"
#include "pcap.h"


pid_t pid;
u16 icmp_req = 1;
struct timeval stop,start,middle;
	
void print_usage()
{
	printf("Please enter the following command.\n");
	printf("sudo ./ipscanner –i [Network Interface Name] -t [timeout(ms)]\n");
}

int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	
	pid = getpid();
	struct sockaddr_in dst;
	// myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	
	
	int sockfd_send, sockfd_recv;
	struct in_addr myip,mymask;
	struct ifreq req; 
	char device_name[100];
	myicmp packet,packet_recv;

	strcpy(device_name,argv[2]);
	strcpy(req.ifr_name, device_name);
	timeout = atoi(argv[4]);
	
	
	//檢查是否為root
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}
	//開啟傳送socket
	if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(1);
	}
	//紀錄source ip到myip
    if(ioctl(sockfd_send, SIOCGIFADDR, &req) < 0) {
        perror("ioctl SIOCGIFADDR error");
		exit(1);
    }
	else{
		memcpy(&dst,&req.ifr_addr,sizeof(dst));
		myip = dst.sin_addr;
	}
	//紀錄source mask到mymask
	if( ioctl(sockfd_send,SIOCGIFNETMASK, &req)== -1){
		perror("SIOCGIFADDR ERROR");
		exit(1);
	}
	else{
		memcpy(&dst,&req.ifr_addr,sizeof(dst));
        mymask = dst.sin_addr;
	}
	
	char str_IP[INET_ADDRSTRLEN];
	char str_Mask[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &myip, str_IP, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &mymask, str_Mask, INET_ADDRSTRLEN);

	// printf("myip = %s \n",str_IP );
	// printf("mymask = %s \n",str_Mask);

	char maskStr[15];
	unsigned int Target_Mask[4]; ///用來存subnet mask用.分開的int
	memcpy(maskStr, str_Mask, 15);
	char *Mask_token;
	int MASK_Num;
	Mask_token = strtok(maskStr, "."); //取.分割後的第一串string
	int i=0;
	while( Mask_token != NULL)  //繼續取分割後面的直到取完
	{
		MASK_Num = atoi(Mask_token);
		//printf("Mask token = %s \n",Mask_token ); 
		Target_Mask[i] = MASK_Num;
		i++;
		Mask_token = strtok(NULL,".");
	}
	// printf("Target_Mask = %d \n",Target_Mask[3] );

	char ipStr[15];
	unsigned int Target_IP[4]; //存subnet mask用.分開的int
	memcpy(ipStr, str_IP, 15);
	char *IP_token;
	int IP_Num;
	IP_token = strtok(ipStr, ".");
	int j=0;
	while( IP_token != NULL) 
	{
		IP_Num = atoi(IP_token);
		Target_IP[j] = IP_Num;
		j++;
		IP_token = strtok(NULL,".");
	}
	// printf("Target_IP = %d \n",Target_IP[0]);	
	

	// uint32_t start_ip, end_ip;
	// start_ip = (myip.s_addr & mymask.s_addr) + 0x01000000;
	// end_ip = (0xffffffff ^ mymask.s_addr) + start_ip - 0x02000000;

	//network轉presentation(string)檢查
	// char p_start_ip[INET_ADDRSTRLEN];
	// inet_ntop(AF_INET, &start_ip, p_start_ip, INET_ADDRSTRLEN);
	// printf("start_ip = %s \n",p_start_ip);

	// char p_end_ip[INET_ADDRSTRLEN];
	// inet_ntop(AF_INET, &end_ip, p_end_ip, INET_ADDRSTRLEN);
	// printf("end_ip = %s \n",p_end_ip);


	int begin,end;

	begin = (Target_IP[3] & Target_Mask[3]) + 1;
	end = (255 ^ Target_Mask[3]) + begin -2;
	// printf("begin = %d \n",begin);
	// printf("end = %d \n",end);

	if(argc == 5){
		if(!strcmp(argv[0],"./ipscanner") && !strcmp(argv[1],"-i") && !strcmp(argv[3],"-t")){
			

			//從begin到end的host傳送icmp封包
			for(int i=begin; i<=end; i++){
				char current_IP[15];
				sprintf(current_IP,"%d.%d.%d.%d",Target_IP[0],Target_IP[1],Target_IP[2],i);
				
				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0){
					perror("socket");
					exit(1);
				}
				if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
					perror("setsockopt");
					exit(1);
				}		

				char data[20] = "M103040072";
				dst.sin_family = AF_INET;
				dst.sin_addr.s_addr = inet_addr(current_IP);


				//填IP和ICMP header
				fill_icmphdr(&packet.icmp_all,data);
				fill_iphdr(&packet.ip_hdr, current_IP,str_IP,sizeof(packet));

				//set timer檢查送出到收到reply時間
				unsigned long timeUsec;
				unsigned long timeSec;
				gettimeofday(&start, NULL);
				
				if(sendto(sockfd, &packet, sizeof(packet), 0, &dst, sizeof(dst)) < 0)
				{
					perror("sendto");
					exit(1);
				}
				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0)
				{
					perror("socket");
					exit(1);
				}
				//設定timeout
				middle.tv_sec = timeout/1000;
				middle.tv_usec = timeout%1000;
				bzero(&dst,sizeof(dst));

				printf("Ping %s (data size = %ld, id = 0x%x, seq = %d, timeout = %d ms)\n", current_IP, sizeof(packet.icmp_all.icmp_data),pid,icmp_req,timeout);

				
				//接收封包
				while(1){
					if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&middle,sizeof(struct timeval)) >-1){
						if(recvfrom(sockfd, &packet, sizeof(packet), 0,  NULL, NULL) < 0){
							printf("Destination Unreachable\n\n");
							break;
						}
						gettimeofday(&stop, NULL);
						timeSec = stop.tv_sec-start.tv_sec;
						timeUsec =(stop.tv_usec-start.tv_usec);
						if(ntohs(packet.icmp_all.icmp_type) == ICMP_ECHOREPLY )
						{
							printf("Reply from : %s , time : %ld.%04ld ms\n\n",current_IP,timeSec,timeUsec);
							break;
						}							
			    	}

				}
				icmp_req++;
			}
		}
		else{
			print_usage();
			exit(1);		
		}
	}
	else{
		print_usage();
		exit(1);
	}
	return 0;
}

