#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h>
#include <libnet.h>
#include <string.h>
#include <pcap.h>
#include <list>






struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct ieee_header {	//https://docs.huihoo.com/doxygen/linux/kernel/3.7/structieee80211__header.html
    uint8_t subtype;
    uint8_t flags;
    uint16_t duration_id;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    uint16_t seq_ctl;
    uint8_t payload[0];
} __attribute__((__packed__)); 

struct ieee_data {
    uint8_t fix[12];
	uint8_t e_id;
	uint8_t len;
	uint8_t ssid[32];
} __attribute__((__packed__)); 

struct node{
	int beacons;
    uint8_t bssid[6];
	uint8_t ssid_len;
	uint8_t ssid[32];
}; 
