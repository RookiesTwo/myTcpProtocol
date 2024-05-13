package top.rookiestwo;

import org.pcap4j.core.*;

import java.net.InetAddress;
import java.nio.ByteBuffer;
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

    private boolean serverFinFlag;

    private ByteBuffer inputBuffer;

    public TCPLink(InetAddress srcAddr,InetAddress dstAddr,int dstPort) throws PcapNativeException, UnknownHostException, NotOpenException, InterruptedException {
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
        handle.setFilter("tcp and src host "+dstAddr.getHostName()+" and src port 80 and dst port "+Integer.toString(this.srcPort),BpfProgram.BpfCompileMode.OPTIMIZE);

        serverFinFlag=false;

        inputBuffer=ByteBuffer.allocate(8192);

        //建立三次握手
        tcpHandshake();



        close();
    }

    //三次握手，建立连接
    private void tcpHandshake() throws UnknownHostException, NotOpenException, PcapNativeException {
        //发包
        handle.sendPacket(buildHandShakePacket());
        byte[] secondPacket;
        while(true){
            secondPacket=handle.getNextRawPacket();
            if(secondPacket!=null)break;
        }
        //输出
        System.out.println("接收到的第二个包：");
        printHex(secondPacket);
        //解析收到的包
        TCPPacket secondTcpPacket=new TCPPacket(secondPacket);

        //进行操作
        if(secondTcpPacket.getSyn()&&secondTcpPacket.getAcknowledgement()){
            this.ackNum=secondTcpPacket.getSequenceNum();
            this.ackNum++;
            this.seqNum++;
            this.identificationID++;
        }

        handle.sendPacket(buildHandShakePacket());
        System.out.println("已成功进行三次握手!");
    }
    //构建握手数据包
    private byte[] buildHandShakePacket() throws UnknownHostException {
        TCPPacket tcpPacket=new TCPPacket(this.dstAddr.getHostName(),this.dstPort,this.srcPort,this.seqNum,this.ackNum,new byte[0]);
        if(this.ackNum==0){
            tcpPacket.setMaxSegmentSize(1460);
            tcpPacket.setWindowScale((byte)8);
            tcpPacket.setSACK();
            tcpPacket.setSyn(true);
        }
        if(this.ackNum!=0){
            tcpPacket.setAcknowledgement(true);
        }
        tcpPacket.fillChecksum();

        IPPacket IPPacket=new IPPacket(this.dstAddr.getHostName(),identificationID,tcpPacket.getTCPPacket());
        EthernetPacket EthernetPacket=new EthernetPacket(IPPacket.getIPPacket());
        return EthernetPacket.getEthernetPacket();
    }

    //四次挥手
    private void close() throws UnknownHostException, NotOpenException, PcapNativeException {
        handle.sendPacket(buildClosePacket());
        TCPPacket tcpPacket;
        byte[] temp;
        while(true){
            temp=handle.getNextRawPacket();
            if(temp==null)continue;
            else tcpPacket=new TCPPacket(temp);
            //接收到服务端的Fin信号后
            if(tcpPacket.getFin()){
                serverFinFlag=true;
                this.seqNum++;
                this.ackNum++;
                this.identificationID++;
                break;
            }
            inputBuffer.put(tcpPacket.getPayload());
        }
        //最后发送认可服务器结束的包
        handle.sendPacket(buildClosePacket());
    }

    //构建挥手数据包
    private byte[] buildClosePacket() throws UnknownHostException {
        TCPPacket tcpPacket=new TCPPacket(this.dstAddr.getHostName(),this.dstPort,this.srcPort,this.seqNum,this.ackNum,new byte[0]);
        if(!this.serverFinFlag){
            tcpPacket.setFin(true);
        }
        if(this.ackNum!=0){
            tcpPacket.setAcknowledgement(true);
        }
        tcpPacket.fillChecksum();

        IPPacket IPPacket=new IPPacket(this.dstAddr.getHostName(),identificationID,tcpPacket.getTCPPacket());
        EthernetPacket EthernetPacket=new EthernetPacket(IPPacket.getIPPacket());
        return EthernetPacket.getEthernetPacket();
    }
    //打印数据包用的方法
    public static void printHex(byte[] bytes) {
        int i=0;
        for (byte b : bytes) {
            System.out.print(String.format("%02X ", b));
            i++;
            if(i%8==0)System.out.print("  ");
            if(i%16==0)System.out.println();
        }
        System.out.println();
    }
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
