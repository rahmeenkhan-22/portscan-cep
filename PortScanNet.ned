

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.StandardHost;
import inet.node.inet.Router;
import inet.node.ethernet.Eth100M;
import inet.node.ethernet.EthernetSwitch;

network PortScanNet
{
    parameters:
        int numVictims = default(3);
    submodules:
        client: StandardHost;
        configurator: Ipv4NetworkConfigurator;
        attacker: StandardHost;
        gateway: Router;
        switch: EthernetSwitch;
        victim[numVictims]: StandardHost;
    connections:
        gateway.ethg++ <--> Eth100M <--> client.ethg++;
        attacker.ethg++ <--> Eth100M <--> gateway.ethg++;
        gateway.ethg++ <--> Eth100M <--> switch.ethg++;
        for i=0..numVictims-1 {
            switch.ethg++ <--> Eth100M <--> victim[i].ethg++;
        }
}//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
