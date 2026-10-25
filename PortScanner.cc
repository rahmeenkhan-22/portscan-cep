#include "PortScanner.h"

Define_Module(PortScanner);

void PortScanner::initialize(int stage)
{
    UdpBasicApp::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        startPort = par("startPort");
        endPort = par("endPort");
        scanInterval = par("scanInterval");
        scanMode = par("scanMode").stdstringValue();

        if (startPort < 1 || endPort > 65535 || startPort > endPort)
            throw cRuntimeError("Invalid port range %d-%d", startPort, endPort);
        if (scanMode != "sequential" && scanMode != "random" && scanMode != "stealth")
            throw cRuntimeError("Invalid scanMode '%s'", scanMode.c_str());

        for (int p = startPort; p <= endPort; p++)
            ports.push_back(p);

        // random and stealth probe the ports in shuffled order, using OMNeT++'s RNG
        if (scanMode != "sequential") {
            for (int i = (int)ports.size() - 1; i > 0; i--) {
                int j = intuniform(0, i);
                std::swap(ports[i], ports[j]);
            }
        }
    }
}

void PortScanner::processSend()
{
    if (nextIndex >= ports.size())
        return;

    destPort = ports[nextIndex++];      // choose this probe's destination port
    sendPacket();                       // UdpBasicApp sends one UDP packet to destPort

    simtime_t dt = (lastProbeTime < 0) ? SIMTIME_ZERO : simTime() - lastProbeTime;
    EV_INFO << "PortScanner probe " << numSent << " mode=" << scanMode
            << " port=" << destPort << " t=" << simTime() << " dt=" << dt << "\n";
    lastProbeTime = simTime();

    if (nextIndex < ports.size()) {
        // stealth adds jitter so the probes are not perfectly regular
        simtime_t gap = (scanMode == "stealth") ? scanInterval * uniform(0.5, 1.5) : scanInterval;
        selfMsg->setKind(SEND);
        scheduleAt(simTime() + gap, selfMsg);
    }
    else {
        scanEndTime = simTime();
    }
}

void PortScanner::finish()
{
    UdpBasicApp::finish();
    recordScalar("probesSent", numSent);
    recordScalar("scanEndTime", scanEndTime.dbl());
    EV_INFO << "PortScanner finished: " << numSent << " probes sent\n";
}
