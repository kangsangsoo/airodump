#include <pcap.h>
#include <iostream>
#include <cstdio>
#include "hd.h"
#include <map>

using namespace std;

map <Mac, int> beacon_count;
map <Mac, string> essid;


void usage(void) {
	cout << "syntax : airodump <interface>" << endl;
	cout << "sample : airodump mon0" << endl;
}

void print(void) {
	printf("\x1b[H\x1b[J");
	for(auto it = beacon_count.begin(); it != beacon_count.end(); it++) {
		cout << string(it->first) << '\t' << it->second << '\t' << essid[it->first] << endl;
	}
}


#define ESSID 0
string null_string;
string find_essid(const u_char* tag_start, int tag_total_len) {
	// tag_number + tag_length + tag_content

	cout << "essid" << endl;
	int i = 0;
	while(i < tag_total_len-4) {
		uint8_t tag_number = tag_start[i++];
		uint8_t tag_length = tag_start[i++];

		if(tag_number == ESSID) {
			// i ~ i + tag_length
			string str;
			int limit = i + tag_length;
			// essid가 다 \0인 경우는?
			for(;i < limit; i++) {
				str.push_back(tag_start[i]);
			}
			cout << str << endl;
			return str;
		}  
		i = i + tag_length;
	}

	return null_string;
}

int main(int argc, char* argv[]) {
	if(argc != 2) {
		usage();
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
		return -1;
	}

	struct pcap_pkthdr* pkheader;
	const u_char* packet;

	while(1) {
		int res = pcap_next_ex(handle, &pkheader, &packet); 

		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

		// beacon인지 아닌지

		radiotap_header* rh = (radiotap_header*)packet;
		beacon_frame* bf = (beacon_frame*)(packet + (rh->len_));

		if(bf->type_ == BEACON) {
			beacon_count[bf->bssid_]++;
			if(essid.find(bf->bssid_) != essid.end()) continue;
			string result = find_essid(packet + (rh->len_) + sizeof(beacon_frame), pkheader->len - (rh->len_) - sizeof(beacon_frame)); 
			if(result == null_string) continue;
			essid[bf->bssid_] = result;
		}

		else if(bf->type_ = DATA) {
			data_frame* df = (data_frame*)(packet + ntohs(rh->len_));

		}
		
		print();

	}
	
}