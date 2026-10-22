import inet.applications.udpapp.UdpBasicApp;

simple PortScanner extends UdpBasicApp
{
    parameters:
        int startPort = default(1);
        int endPort = default(1024);
        double scanInterval @unit(s) = default(0.05s);
        string scanMode = default("sequential");  // "sequential" | "random" | "stealth"
        destPort = default(1);               // overwritten for each probe
        messageLength = default(32B);
        sendInterval = default(1s);          // unused, scanInterval replaces it
        @class(PortScanner);
        @display("i=block/app");
}