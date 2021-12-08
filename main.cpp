#include <pcap.h>
#include <iostream>
#include <cstdio>
#include "802-11.h"
#include <map>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <regex>

using namespace std;

#define BEACON 8
#define PROBE_REQEUST 4
#define MANAGEMENT_FRAME 0
#define SSID 0

int channel;
map <Mac, int> beacon_count;
map <Mac, string> essid;
map <string, Mac> essid_rev;
map <pair<Mac, Mac>, string> ap;

void usage(void) {
	cout << "syntax : airodump <interface>" << '\n';
	cout << "sample : airodump mon0" << '\n';
}

void print(void) {
	system("clear");
	printf("CHANNEL: %d\n", channel);
	cout << "BSSID\t\t\tBEACON\t\tESSID\n\n";
	for(auto it = beacon_count.begin(); it != beacon_count.end(); it++) {
		cout << string(it->first) << '\t' << it->second << "\t\t" << essid[it->first] << '\t' << '\n';
	}
	cout << "\nBSSID\t\t\tSTATION\t\t\t\tPROBE\n\n";
	for(auto it = ap.begin(); it != ap.end(); it++) {
		if(it->first.first == Mac::broadcastMac()) cout << "(not associated)"<< "\t" << string(it->first.second) << "\t\t" << it->second << '\t' << '\n';
		else cout << string(it->first.first) << '\t' << string(it->first.second) << "\t\t" << it->second << '\t' << '\n';
	}
}

void channel_hopping_thread(char* dev) {
	string a = string("iwlist ") + string(dev) + string(" channel");

	/* wanochoi.com/?p=178 */
	FILE* stream = popen(a.c_str(), "r" ); 
	ostringstream output;
	 while( !feof(stream) && !ferror(stream) )
	{
		char buf[128];
		int bytesRead = fread( buf, 1, 128, stream );
		output.write( buf, bytesRead );
	}
	pclose(stream);
	string result = output.str();
	/**/

	vector <string> ch_list;
	regex re("Channel [\\d]+ ");

	auto it = sregex_iterator(result.begin(), result.end(), re);
	for(;it != sregex_iterator(); it++) {
		ch_list.push_back(it->str().substr(8, it->str().length() - 9));
	}

	while(1) {
		for(auto i : ch_list) {
			channel = atoi(i.c_str());
			string s = string("iwconfig ") + string(dev) + string(" channel ") + i;
			system(s.c_str());
			std::this_thread::sleep_for( std::chrono::milliseconds(500) ) ;
		}
	}
}

string find_essid(const u_char* tag_start, int tag_total_len) {
	tagged_parameter* tag = (tagged_parameter*)tag_start;

	if(tag->id_ != SSID) return string("");
	
	string s;
	for(int i = 0; i < tag->len_; i++) s.push_back(tag_start[2+i]);
	return s;
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

		// probe request
		if(pf->type_ == MANAGEMENT_FRAME && pf->subtype_ == PROBE_REQEUST) {
			auto str = find_essid(packet + (rh->len_) + sizeof(probe_frame), pkheader->len - (rh->len_) - sizeof(probe_frame));
			if(essid_rev.find(str) == essid_rev.end()) ap.insert({{Mac::broadcastMac(), pf->sa_}, str});
			else ap.insert({{essid_rev[str], bf->sa_}, str});
		}

		// beacon frame
		else if(bf->type_ == MANAGEMENT_FRAME && bf->subtype_ == BEACON) {
			beacon_count[bf->bssid_]++;
			if(essid.find(bf->bssid_) == essid.end()) {
				essid[bf->bssid_] = find_essid(packet + (rh->len_) + sizeof(beacon_frame), pkheader->len - (rh->len_) - sizeof(beacon_frame)); 
				essid_rev[essid[bf->bssid_]] = bf->bssid_;
			}
		}

		print();
	}

	pcap_close(handle);
	return 0;
}
