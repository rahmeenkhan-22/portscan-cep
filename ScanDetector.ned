import inet.common.SimpleModule;

simple ScanDetector extends SimpleModule
{
    parameters:
        @class(ScanDetector);
        bool detectorEnabled = default(true);
        int threshold = default(10);
        double windowSize @unit(s) = default(5s);
        string networkProtocolModule = default("^.ipv4.ip");
        string victimAddresses = default("10.0.0.10 10.0.0.11 10.0.0.12");
        string attackerAddress = default("10.0.0.5");
}
