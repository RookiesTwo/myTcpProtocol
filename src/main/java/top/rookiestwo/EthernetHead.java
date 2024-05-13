package top.rookiestwo;

import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.nio.ByteBuffer;

import static top.rookiestwo.MyTcpProtocolMain._2ByteArrayBuild;

public class EthernetHead {

    MacAddress hostMAC;
    MacAddress gatewayMAC;

    public EthernetHead() {
        //获得MAC
        hostMAC=MyTcpProtocolMain.hostMAC;
        gatewayMAC=MyTcpProtocolMain.gatewayMAC;
    }

    public byte[] autoBuild(){
        //构建以太网header
        byte[] gatewayBytes=MyTcpProtocolMain.gatewayMAC.getAddress();
        byte[] hostBytes=hostMAC.getAddress();
        //ipv4
        byte[] etherType=_2ByteArrayBuild(0x0800);

        //合为一个字节数组
        ByteBuffer buffer=ByteBuffer.allocate(14);
        buffer.put(gatewayBytes).put(hostBytes).put(etherType);

        return buffer.array();
    }
}
