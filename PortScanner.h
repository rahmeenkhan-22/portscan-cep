#ifndef __PORTSCANNER_H
#define __PORTSCANNER_H

#include <string>
#include <vector>
#include "inet/applications/udpapp/UdpBasicApp.h"

using namespace inet;

class PortScanner : public UdpBasicApp
{
  protected:
    int startPort = 1;
    int endPort = 1024;
    simtime_t scanInterval;
    std::string scanMode;
    std::vector<int> ports;     // probe order
    size_t nextIndex = 0;
    simtime_t scanEndTime = -1;
    simtime_t lastProbeTime = -1;

    virtual void initialize(int stage) override;
    virtual void processSend() override;
    virtual void finish() override;
};

#endif
