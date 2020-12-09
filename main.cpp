#include "airodump.h"


std::list<node*> node_list;

void usage(void){
    puts("syntax : airodump <interface>");
    puts("sample : airodump mon0");
}


void myprint(){
	write(1, "\033[1;1H\033[2J", 10);	// 출처 : https://wowcat.tistory.com/1487
	printf("BBSID\t\t\tBeacons\t\t\tESSID\n\n");
	for (node *tmp : node_list){
        for(int i = 0; i < 6; i++){
        	printf("%02X",tmp->bssid[i]);
        	if(i == 5)
        		break;
        	printf(":");
        }

        printf("\t");
        printf("%d",tmp->beacons);

        printf("\t\t\t");

        for(int i = 0; i < tmp->ssid_len; i++){
        	printf("%c",tmp->ssid[i]);
        }
        printf("\n");

	}
}


int main(int argc, char **argv){
	if(argc != 2){
		usage();
		exit(1);
	}

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while(true){
    	myprint();
    	struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct ieee80211_radiotap_header* ir_hdr = (struct ieee80211_radiotap_header*) packet;
        struct ieee_header* i_hdr = (struct ieee_header*)(packet + (ir_hdr->it_len));

        if(i_hdr -> subtype != 0x80)
        	continue;

        struct ieee_data* data_fr = (struct ieee_data*)((uint8_t*) i_hdr + sizeof(struct ieee_header));
        


        int chk = 0;

        for (node *tmp : node_list){
        	if(!memcmp(tmp->bssid,i_hdr->bssid,6)){
        		tmp->beacons = tmp->beacons + 1;
        		//printf("=====================%d====================\n",tmp.beacons);
        		chk = 1;
        		break;
        	}
		}

		if(chk)
			continue;

		//printf("+++++++++++++++++++\n");
		struct node* test = (node*)malloc(sizeof(node));

        memcpy(test->bssid,i_hdr->bssid,6);
        test->beacons = 1;
        test->ssid_len = data_fr->len;
        memcpy(test->ssid, data_fr->ssid, data_fr->len);
        node_list.push_back(test);

    }	

}