package top.rookiestwo;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import static top.rookiestwo.MyTcpProtocolMain._2ByteArrayBuild;

public class IPPacket {
    private byte versionAndHeaderLength;

    private byte serviceType; // 服务类型

    private byte[] totalLength; // 总长度(包含数据包负载的总长度)

    private byte[] identification;//identification,第一个包是1~65535之间的随机值

    private byte[] flagsAndFragmentOffset;// 标志和片偏移,不偏移，不分片因此后两位为00，前两位为40

    private byte ttl;// TTL,一般设定为128次

    private byte protocol;// 协议,TCP为6,即0x06

    private byte[] checksum;// 校验和

    private byte[] srcIP;//本机IP

    private byte[] dstIP;//目标IP

    private byte[] payload;//负载

    private InetAddress hostIP;
    private InetAddress destinationIP;

    public IPPacket(String DstIP, int identificationID, byte[] Payload) throws UnknownHostException {
        //初始化
        hostIP = MyTcpProtocolMain.hostIP;
        destinationIP = Inet4Address.getByName(DstIP);

        //填入默认值
        versionAndHeaderLength = (byte) 0x45;
        serviceType = (byte) 0x00;
        totalLength = _2ByteArrayBuild(0);//暂且为0
        identification = _2ByteArrayBuild(identificationID); // 有可能要分片，分片后续再处理
        flagsAndFragmentOffset = _2ByteArrayBuild(0x4000);// 标志和片偏移,不偏移，不分片因此后两位为00，前两位为40
        ttl = (byte) 0x80;
        protocol = (byte) 0x06;//TCP为6
        checksum = _2ByteArrayBuild(0x0000);//后续
        srcIP = Inet4Address.getByName(hostIP.getHostAddress()).getAddress();//填入本机IP
        dstIP = Inet4Address.getByName(destinationIP.getHostAddress()).getAddress();//填入目标IP
        payload = Payload;
        this.postProcess();
    }

    public IPPacket(byte[] rawPacket) {
        versionAndHeaderLength = rawPacket[14];
        serviceType = rawPacket[15];
        totalLength = new byte[2];
        System.arraycopy(rawPacket, 16, totalLength, 0, 2);
        identification = new byte[2];
        System.arraycopy(rawPacket, 18, identification, 0, 2);
        flagsAndFragmentOffset = new byte[2];
        System.arraycopy(rawPacket, 20, flagsAndFragmentOffset, 0, 2);
        ttl = rawPacket[22];
        protocol = rawPacket[23];
        checksum = new byte[2];
        System.arraycopy(rawPacket, 24, checksum, 0, 2);
        srcIP = new byte[4];
        System.arraycopy(rawPacket, 26, srcIP, 0, 4);
        dstIP = new byte[4];
        System.arraycopy(rawPacket, 30, srcIP, 0, 4);
        int temp = (totalLength[0] << 8) + totalLength[1];
        payload = new byte[temp - 20];
        System.arraycopy(rawPacket, 34, identification, 0, temp - 20);
    }

    //checksum值的计算
    //https://stackoverflow.com/questions/4113890/how-to-calculate-the-internet-checksum-from-a-byte-in-java
    public static byte[] calculateChecksum(byte[] inputData) {
        int length = inputData.length;
        int i = 0;
        long sum = 0;
        long data;
        // 处理所有的成对的byte
        while (length > 1) {
            // Corrected to include @Andy's edits and various comments on Stack Overflow
            data = (((inputData[i] << 8) & 0xFF00) | ((inputData[i + 1]) & 0xFF));
            sum += data;
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
            i += 2;
            length -= 2;
        }
        // 处理奇数byte的情况
        if (length > 0) {
            sum += (inputData[i] << 8 & 0xFF00);
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
        }
        // 反转并取两位
        sum = ~sum;
        sum = sum & 0xFFFF;
        return _2ByteArrayBuild((int) sum);
    }

    //获取IPHead的字节数组
    public byte[] getIPHead() {
        ByteBuffer buffer = ByteBuffer.allocate(20);
        buffer.put(versionAndHeaderLength)
                .put(serviceType)
                .put(totalLength)
                .put(identification)
                .put(flagsAndFragmentOffset)
                .put(ttl)
                .put(protocol)
                .put(checksum)
                .put(srcIP)
                .put(dstIP);
        return buffer.array();
    }

    //IP头后处理，先计算总长度，再计算CheckSum
    public void postProcess() {
        fillTotalLength();
        fillChecksum();
    }

    //计算大小
    public void fillTotalLength() {
        totalLength = _2ByteArrayBuild(20 + payload.length);
    }

    //必须先计算TotalLength后才能调用
    public void fillChecksum() {
        checksum = _2ByteArrayBuild(0);
        ByteBuffer buffer = ByteBuffer.allocate(20 + payload.length);
        buffer.put(getIPHead()).put(payload);
        checksum = calculateChecksum(buffer.array());
    }
}