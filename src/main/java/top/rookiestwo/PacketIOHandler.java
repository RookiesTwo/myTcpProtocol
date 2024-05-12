package top.rookiestwo;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class PacketIOHandler {
    PcapNetworkInterface nif;
    int snapLen = 65536;
    PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
    public PacketIOHandler() throws PcapNativeException {
        nif = Pcaps.getDevByAddress(MyTcpProtocolMain.hostIP);
    }
}
