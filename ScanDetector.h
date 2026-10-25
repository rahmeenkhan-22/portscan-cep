#ifndef __SCANDETECTOR_H
#define __SCANDETECTOR_H

#include <map>
#include <set>
#include <deque>
#include <string>
#include <vector>

#include "inet/common/SimpleModule.h"
#include "inet/common/ModuleRefByPar.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/common/L3Address.h"

using namespace inet;

class ScanDetector : public SimpleModule, public NetfilterBase::HookBase
{
  protected:
    struct Hit { simtime_t time; int port; };
    struct SrcState {
        std::deque<Hit> hits;
        long probesSeen = 0;
        bool flagged = false;
    };
    struct FlagRow { simtime_t time; std::string src; int distinctPorts; long probes; };

    bool detectorEnabled = true;
    int threshold = 10;
    simtime_t windowSize = 5;
    ModuleRefByPar<INetfilter> networkProtocol;

    std::set<std::string> victims;
    std::string attacker;
    std::map<std::string, SrcState> sources;
    std::vector<FlagRow> flagRows;

    simtime_t firstFlagTime = -1;
    long probesBeforeFlag = -1;
    int maxDistinctPorts = 0;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    virtual Result processPacket(Packet *packet, INetfilter::IHook::Type type);

  public:
    virtual Result datagramPreRoutingHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramForwardHook(Packet *datagram) override { return processPacket(datagram, FORWARD); }
    virtual Result datagramPostRoutingHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalInHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalOutHook(Packet *datagram) override { return ACCEPT; }
};

#endif
