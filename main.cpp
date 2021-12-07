#include <pcap.h>
#include <iostream>
#include <cstdio>
#include "hd.h"
#include <map>
#include <thread>
#include <mutex>
#include <time.h>
#include <unistd.h>

using namespace std;

mutex ch_mutex;

int channel = 1;
// 1~13 1초 간격
void channel_hopping_thread(char* dev) {
	unsigned char i = 0;
	
	while(1) {
		string s;
		s += "iwconfig ";
		s += dev;
		s += " channel ";
		s += to_string(channel);
		
		channel = (i++ % 13) + 1;
		system(s.c_str());

		
		std::this_thread::sleep_for( std::chrono::milliseconds(1000) ) ;
		// sleep(10);
	}
}

map <Mac, int> beacon_count;
map <Mac, string> essid;
map <string, Mac> essid_rev;
map <pair<Mac, Mac>, string> ap;


void usage(void) {
	cout << "syntax : airodump <interface>" << endl;
	cout << "sample : airodump mon0" << endl;
}

void print(void) {
	printf("\x1b[H\x1b[J");

	printf("channel: %d\n", channel);
	printf("bssid\t\t\tbeacon\t\tessid\n\n");
	for(auto it = beacon_count.begin(); it != beacon_count.end(); it++) {
		// printf("%s\t%d\t%s\n", string(it->first).c_str(), it->second, essid[it->first].c_str());
		cout << string(it->first) << '\t' << it->second << "\t\t" << essid[it->first] << '\t' << endl;
	}
	printf("\nbssid\t\t\tap\t\t\t\tprobe\n\n");
	for(auto it = ap.begin(); it != ap.end(); it++) {
		// printf("%s\t%d\t%s\n", string(it->first).c_str(), it->second, essid[it->first].c_str());
		if(it->first.first == Mac::broadcastMac()) cout << "not associated"<< "\t\t" << string(it->first.second) << "\t\t" << it->second << '\t' << endl;
		else cout << string(it->first.first) << '\t' << string(it->first.second) << "\t\t" << it->second << '\t' << endl;
	}
}


#define ESSID 0
string null_string;
string find_essid(const u_char* tag_start, int tag_total_len) {
	// tag_number + tag_length + tag_content

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

	thread* t = new thread(channel_hopping_thread, argv[1]);
	t->detach();

	while(1) {
		int res = pcap_next_ex(handle, &pkheader, &packet); 

		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

		radiotap_header* rh = (radiotap_header*)packet;
		beacon_frame* bf = (beacon_frame*)(packet + (rh->len_));
		probe_frame* pf = (probe_frame*)(packet + (rh->len_));
		if(pf->version_ == 0 && pf->type_ == 0 && pf->subtype_ == 4) {
			auto tmp = find_essid(packet + (rh->len_) + sizeof(probe_frame), pkheader->len - (rh->len_) - sizeof(probe_frame));
			// cout << tmp << endl;
			if(essid_rev.find(tmp) == essid_rev.end()) ap.insert({{Mac::broadcastMac(), pf->sa_}, tmp});
			else ap.insert({{essid_rev[tmp], bf->sa_}, tmp});
		}

		if(bf->version_ != 0 || bf->type_ != 0 || bf->subtype_ != BEACON) continue;
		beacon_count[bf->bssid_]++;
		if(essid.find(bf->bssid_) == essid.end()) {
			essid[bf->bssid_] = find_essid(packet + (rh->len_) + sizeof(beacon_frame), pkheader->len - (rh->len_) - sizeof(beacon_frame)); 
			essid_rev[essid[bf->bssid_]] = bf->bssid_;
			// cout << string(bf->bssid_) << endl;
		}
		print();
	}
	
}