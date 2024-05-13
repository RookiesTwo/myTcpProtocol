package top.rookiestwo;

import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Random;

import static top.rookiestwo.MyTcpProtocolMain._2ByteArrayBuild;
import static top.rookiestwo.MyTcpProtocolMain._4ByteArrayBuild;
import static top.rookiestwo.IPPacket.calculateChecksum;

public class TCPPacket {

    private byte[] srcPort;

    private byte[] dstPort;

    private byte[] sequenceNum;

    private byte[] acknowledgementNumber;

    //————————16位头部长度、标志位————————
    //TCP头部长度，注意仅有4比特存储长度(因此最大为2^4=16字节)，后4比特中：前三比特为保留位，最后一个比特代表AccurateECN //该变量应该仅用get方法调用！
    private int tcpHeaderLength;

    //9个特定标志
    private boolean accurateECN;
    private boolean congestionWindowReduced;
    private boolean ecnEcho;
    private boolean urgent;
    private boolean acknowledgement;
    private boolean push;
    private boolean reset;
    private boolean syn;
    private boolean fin;

    //用于整合上面16位的数组
    private byte[] LengthAndFlags;

    public void setSyn(boolean syn) {
        this.syn = syn;
        this.setLengthAndFlags();
    }
    public void setFin(boolean fin) {
        this.fin = fin;
        this.setLengthAndFlags();
    }
    public void setAcknowledgement(boolean acknowledgement) {
        this.acknowledgement = acknowledgement;
        this.setLengthAndFlags();
    }
    //————————————————————————————————


    private byte[] windowSize;//窗口大小

    private byte[] checksum;//校验和，最后再进行计算

    private byte[] urgentPointer;//紧急指针，通常设为0


    //——————————各种Options——————————
    private byte[] options;
    private byte NOP=(byte)0x01;//Options的占位符

    public void setMaxSegmentSize(int maxSegmentSize) {
        //保留options之前的内容
        ByteBuffer buffer = ByteBuffer.allocate(options.length+4);
        buffer.put(options);
        //添加新字段
        buffer.put((byte)0x02)
                .put((byte)0x04)
                .put(_2ByteArrayBuild(maxSegmentSize));
        options=buffer.array();

        tcpHeaderLength+=4;//因为是高位所以需要加16
        this.setLengthAndFlags();
    }

    public void setWindowScale(byte scale){
        ByteBuffer buffer = ByteBuffer.allocate(options.length+4);
        buffer.put(options);

        buffer.put(NOP)
                .put((byte)0x03)
                .put((byte)0x03)
                .put(_2ByteArrayBuild(scale));
        options=buffer.array();

        tcpHeaderLength+=4;
        this.setLengthAndFlags();
    }

    public void setSACK(){
        ByteBuffer buffer = ByteBuffer.allocate(options.length+4);
        buffer.put(options);

        buffer.put(NOP)
                .put(NOP)
                .put((byte)0x04)
                .put((byte)0x02);
        options=buffer.array();

        tcpHeaderLength+=4;
        this.setLengthAndFlags();
    }
    //——————————————————————————————

    private byte[] payload;

    //用于构建伪首部的IP信息
    private InetAddress srcIP;
    private InetAddress dstIP;

    public TCPPacket(String DstIP,int DstPort,int SrcPort, long SeqNum, long AckNum, byte[] Payload) throws UnknownHostException {
        //初始化
        srcIP=MyTcpProtocolMain.hostIP;
        dstIP=InetAddress.getByName(DstIP);

        srcPort=_2ByteArrayBuild(SrcPort);
        dstPort=_2ByteArrayBuild(DstPort);
        sequenceNum= _4ByteArrayBuild(SeqNum);
        acknowledgementNumber= _4ByteArrayBuild(AckNum);

        tcpHeaderLength=20;//默认设为20，有选项添加时在添加选项的方法添加

        accurateECN=false;
        congestionWindowReduced=false;
        ecnEcho=false;
        urgent=false;
        acknowledgement=false;
        push=false;
        reset=false;
        syn=false;
        fin=false;

        this.setLengthAndFlags();

        windowSize=_2ByteArrayBuild(8192);//默认设为8192，不对劲以后再说
        checksum=_2ByteArrayBuild(0);//后续处理
        urgentPointer=_2ByteArrayBuild(0);//默认设为0

        options=new byte[0];

        payload=Payload;
    }

    //将HeaderLength和9个标志位装进2字节数组里
    private void setLengthAndFlags(){
        int headerFlagsTemp = 0;
        // 将TCP头部长度左移12位（16 - 4）
        headerFlagsTemp |= (tcpHeaderLength & 0x0000FFFF) << 12;

        // 填充9个标志位
        headerFlagsTemp |= ((accurateECN ? 1 : 0)) << 8;
        headerFlagsTemp |= (congestionWindowReduced ? 1 : 0) << 7;
        headerFlagsTemp |= (ecnEcho ? 1 : 0) << 6;
        headerFlagsTemp |= (urgent ? 1 : 0) << 5;
        headerFlagsTemp |= (acknowledgement ? 1 : 0) << 4;
        headerFlagsTemp |= (push ? 1 : 0) << 3;
        headerFlagsTemp |= (reset ? 1 : 0) << 2;
        headerFlagsTemp |= (syn ? 1 : 0) << 1;
        headerFlagsTemp |= (fin ? 1 : 0);

        //将TCP头部长度和标志位都装入字节数组内
        LengthAndFlags = _2ByteArrayBuild(headerFlagsTemp);
    }

    //获取整个TCP包
    public byte[] getTCPPacket(){
        ByteBuffer buffer = ByteBuffer.allocate(tcpHeaderLength+payload.length);
        buffer.put(srcPort)
                .put(dstPort)
                .put(sequenceNum)
                .put(acknowledgementNumber)
                .put(LengthAndFlags)
                .put(windowSize)
                .put(checksum)
                .put(urgentPointer)
                .put(options)
                .put(payload);
        return buffer.array();
    }

    public void fillChecksum(){
        checksum=_2ByteArrayBuild(0);
        ByteBuffer buffer = ByteBuffer.allocate(/*伪首部*/12+ tcpHeaderLength + payload.length);
        //伪首部
        buffer.put(srcIP.getAddress())
                .put(dstIP.getAddress())
                .put((byte) 0x00)//全零占位
                .put((byte) 0x06)//tcp协议编号6
                .put(_2ByteArrayBuild(tcpHeaderLength + payload.length));//tcp实际报文和头部的长度和
        buffer.put(this.getTCPPacket());
        checksum = calculateChecksum(buffer.array());
    }

    //判断指定端口是否可用
    public static boolean isPortAvailable(int portNumber) {
        if (portNumber > 65535 || portNumber < 0) return false;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //随机生成一个全新的sequenceNumber，并装进byte数组
    private byte[] generateNewSequenceNumber() {
        Random rand = new Random();
        long sequenceNumber = 0;
        long quarter = 0xFFFFFFFFL / 4;
        while (sequenceNumber < quarter || sequenceNumber > quarter * 3) {
            sequenceNumber = rand.nextLong() & 0xFFFFFFFFL;
        }
        return _4ByteArrayBuild(sequenceNumber);
    }
}
