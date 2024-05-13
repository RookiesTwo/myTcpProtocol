package top.rookiestwo;

import org.pcap4j.core.*;

import java.net.SocketException;
import java.net.UnknownHostException;

public class PacketIOHandler {

    PcapNetworkInterface nif;
    int snapLen = 65536;
    PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
    PcapHandle handle=null;

    public PacketIOHandler() throws PcapNativeException {
        nif = Pcaps.getDevByAddress(MyTcpProtocolMain.hostIP);
        handle=nif.openLive(snapLen, mode, MyTcpProtocolMain.timeoutTime);
    }

    public void sendPacket(byte[] packet) throws SocketException, UnknownHostException, NotOpenException, PcapNativeException {
        MyTcpProtocolMain.requestTimes++;
        handle.sendPacket(packet);


    }
}