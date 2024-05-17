package top.rookiestwo;

import org.pcap4j.util.MacAddress;

import java.nio.ByteBuffer;

import static top.rookiestwo.MyTcpProtocolMain._2ByteArrayBuild;

public class EthernetPacket {

    MacAddress hostMAC;
    MacAddress gatewayMAC;

    byte[] payload;

    public EthernetPacket(byte[] payload) {
        //获得MAC
        hostMAC = MyTcpProtocolMain.hostMAC;
        gatewayMAC = MyTcpProtocolMain.gatewayMAC;

        this.payload = payload;
    }

    public byte[] getEthernetPacket() {
        //构建以太网header
        byte[] gatewayBytes = MyTcpProtocolMain.gatewayMAC.getAddress();
        byte[] hostBytes = hostMAC.getAddress();
        //ipv4
        byte[] etherType = _2ByteArrayBuild(0x0800);

        //将载荷和以太头合为一个字节数组
        ByteBuffer buffer = ByteBuffer.allocate(14 + payload.length);
        buffer.put(gatewayBytes).put(hostBytes).put(etherType).put(payload);

        return buffer.array();
    }
}
