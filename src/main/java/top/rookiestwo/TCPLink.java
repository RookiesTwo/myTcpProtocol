package top.rookiestwo;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;

import java.net.InetAddress;
import java.util.Random;
import java.net.*;

public class TCPLink {
    private InetAddress srcAddr;
    private InetAddress dstAddr;
    private int srcPort;
    private int dstPort;

    private long seqNum;
    private long ackNum;

    private int identificationID;

    private PcapNetworkInterface nif;
    int snapLen = 65536;
    private PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
    private PcapHandle handle;

    public TCPLink(InetAddress srcAddr,InetAddress dstAddr,int dstPort) throws PcapNativeException, UnknownHostException, NotOpenException {
        //初始化
        this.srcAddr=srcAddr;
        this.dstAddr=dstAddr;
        this.srcPort=getRandomPort();
        this.dstPort=dstPort;

        seqNum=generateNewSequenceNumber();
        ackNum=0;

        // 生成一个随机的Identification值（16位）
        Random random = new Random();
        identificationID = random.nextInt(65535);

        nif = Pcaps.getDevByAddress(MyTcpProtocolMain.hostIP);
        handle=nif.openLive(snapLen, mode, MyTcpProtocolMain.timeoutTime);

        //建立三次握手
        startHandshake();
    }

    //三次握手，建立连接
    private void startHandshake() throws UnknownHostException, NotOpenException, PcapNativeException {

        TCPPacket firstTcpPacket=new TCPPacket(this.dstAddr.getHostName(),this.dstPort,this.srcPort,seqNum,ackNum,new byte[0]);
        firstTcpPacket.setMaxSegmentSize(1460);
        firstTcpPacket.setWindowScale((byte)8);
        firstTcpPacket.setSACK();
        firstTcpPacket.setSyn(true);
        firstTcpPacket.fillChecksum();

        IPPacket firstIPPacket=new IPPacket(this.dstAddr.getHostName(),identificationID,firstTcpPacket.getTCPPacket());
        EthernetPacket firstEthernetPacket=new EthernetPacket(firstIPPacket.getIPPacket());
        //发包
        handle.sendPacket(firstEthernetPacket.getEthernetPacket());
    }

    //构建一个完整的TCP数据包
    //private byte[] buildWholeTCPPacket(byte[] payload) throws UnknownHostException {

    //}

    //获取随机端口
    private int getRandomPort(){
        // 定义端口范围
        int minPort = 49153;
        int maxPort = 65535;
        // 创建Random实例
        Random random = new Random();
        // 生成随机端口号
        int randomPort = random.nextInt(maxPort - minPort + 1) + minPort;

        //判断是否可用
        if(isPortAvailable(randomPort)) return randomPort;
        else return getRandomPort();
    }
    //判断指定端口是否可用
    private static boolean isPortAvailable(int portNumber) {
        if (portNumber > 65535 || portNumber < 0) return false;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    //随机生成一个全新的sequenceNumber
    private long generateNewSequenceNumber() {
        Random rand = new Random();
        long sequenceNumber = 0;
        long quarter = 0xFFFFFFFFL / 4;
        while (sequenceNumber < quarter || sequenceNumber > quarter * 3) {
            sequenceNumber = rand.nextLong() & 0xFFFFFFFFL;
        }
        return sequenceNumber;
    }
}
