#include <cstdint>
#include "mac.h"


#define BEACON 8
#define DATA 2 

#pragma pack(push,1)
struct radiotap_header{
	uint8_t version_;
	uint8_t pad_;
	uint16_t len_;
	uint32_t present_;
};
#pragma pack(pop)

#pragma pack(push,1)
struct beacon_frame{
	uint8_t version_:2;
	uint8_t type_:2;
	uint8_t subtype_:4;
	uint8_t flag_;
	uint16_t duration_;
	Mac da_;
	Mac sa_;
	Mac bssid_;
	uint16_t seq_;

	uint64_t timestamp_;
	uint16_t interval_;
	uint16_t ci_;
};
#pragma pack(pop)

#pragma pack(push,1)
struct probe_frame{
	uint8_t version_:2;
	uint8_t type_:2;
	uint8_t subtype_:4;
	uint8_t flag_;
	uint16_t duration_;
	Mac da_;
	Mac sa_;
	Mac bssid_;
	uint16_t seq_;

};
#pragma pack(pop)

#pragma pack(push,1)
struct data_frame{
	uint8_t version_:2;
	uint8_t type_:2;
	uint8_t subtype_:4;
	uint8_t flag_;
	uint16_t duration_;
	Mac da_;
	Mac bssid_;
	Mac sa_;
	uint16_t seq_;
};
#pragma pack(pop)
