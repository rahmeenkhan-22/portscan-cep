import inet.node.inet.Router;

module GatewayRouter extends Router
{
    submodules:
        detector: ScanDetector {
            @display("p=100,100");
        }
}
