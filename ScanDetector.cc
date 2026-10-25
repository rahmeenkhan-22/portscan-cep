#include "ScanDetector.h"

#include <sstream>
#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"
#include "inet/transportlayer/tcp_common/TcpHeader.h"

Define_Module(ScanDetector);

void ScanDetector::initialize(int stage)
{
    SimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        detectorEnabled = par("detectorEnabled");
        threshold = par("threshold");
        windowSize = par("windowSize");
        attacker = par("attackerAddress").stdstringValue();
        std::istringstream iss(par("victimAddresses").stdstringValue());
        std::string ip;
        while (iss >> ip)
            victims.insert(ip);
        networkProtocol.reference(this, "networkProtocolModule", true);
    }
    else if (stage == INITSTAGE_NETWORK_LAYER) {
        if (detectorEnabled) {
            networkProtocol->registerHook(0, this);
            EV_INFO << "ScanDetector: hook registered, threshold=" << threshold
                    << " window=" << windowSize << endl;
        }
    }
}

void ScanDetector::handleMessage(cMessage *msg)
{
    throw cRuntimeError("ScanDetector does not handle messages");
}

INetfilter::IHook::Result ScanDetector::processPacket(Packet *packet, INetfilter::IHook::Type type)
{
    Enter_Method("processPacket");

    // read-only peek, never remove/insert
    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    auto proto = ipv4Header->getProtocol();
    int destPort = -1;

    if (proto == &Protocol::udp) {
        const auto& udp = packet->peekDataAt<UdpHeader>(ipv4Header->getChunkLength());
        destPort = udp->getDestPort();
    }
    else if (proto == &Protocol::tcp) {
        const auto& tcp = packet->peekDataAt<tcp::TcpHeader>(ipv4Header->getChunkLength());
        destPort = tcp->getDestPort();
    }
    else
        return ACCEPT; // ICMP etc ignored

    std::string src = ipv4Header->getSrcAddress().str();
    if (victims.count(src))
        return ACCEPT; // victim replies ignored

    simtime_t now = simTime();
    SrcState& st = sources[src];
    st.probesSeen++;
    st.hits.push_back({now, destPort});

    // slide window
    while (!st.hits.empty() && now - st.hits.front().time >= windowSize)
        st.hits.pop_front();

    std::set<int> distinct;
    for (auto& h : st.hits)
        distinct.insert(h.port);
    int n = (int)distinct.size();
    if (n > maxDistinctPorts)
        maxDistinctPorts = n;

    if (!st.flagged && n > threshold) {
        st.flagged = true;
        flagRows.push_back({now, src, n, st.probesSeen});
        if (firstFlagTime < 0 && src == attacker) {
            firstFlagTime = now;
            probesBeforeFlag = st.probesSeen;
        }
        EV_WARN << "ScanDetector: FLAGGED src=" << src << " distinctPorts=" << n
                << " probes=" << st.probesSeen << " t=" << now << endl;
    }
    return ACCEPT;
}

void ScanDetector::finish()
{
    SimpleModule::finish();
    int falseFlags = 0;
    for (auto& r : flagRows)
        if (r.src != attacker)
            falseFlags++;

    recordScalar("firstFlagTime", firstFlagTime < 0 ? -1.0 : firstFlagTime.dbl());
    recordScalar("probesBeforeFlag", (double)probesBeforeFlag);
    recordScalar("flaggedSources", (double)flagRows.size());
    recordScalar("falseFlags", (double)falseFlags);
    recordScalar("maxDistinctPorts", (double)maxDistinctPorts);

    for (auto& r : flagRows)
        EV_INFO << "FLAGLOG,time=" << r.time << ",sourceIp=" << r.src
                << ",distinctPortsSeen=" << r.distinctPorts
                << ",probesBeforeFlag=" << r.probes << endl;
}
