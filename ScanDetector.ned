import inet.common.SimpleModule;

simple ScanDetector extends SimpleModule
{
    parameters:
        @class(ScanDetector);
        bool detectorEnabled = default(true);
        int threshold = default(10);
        double windowSize @unit(s) = default(5s);
        string networkProtocolModule = default("^.ipv4.ip");
}
