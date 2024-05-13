package top.rookiestwo;

import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Random;

import static top.rookiestwo.MyTcpProtocolMain._2ByteArrayBuild;
import static top.rookiestwo.MyTcpProtocolMain._4ByteArrayBuild;

public class TCPPacket {

    private byte[] srcPort;

    private byte[] dstPort;

    private byte[] sequenceNum;

    private byte[] acknowledgementNumber;

    //————————16位头部长度、标志位————————
    //TCP头部长度，注意仅有4比特存储长度(因此最大为2^4=16字节)，后4比特中：前三比特为保留位，最后一个比特代表AccurateECN //该变量应该仅用get方法调用！
    private byte tcpHeaderLength;

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
    }

    public void setWindowScale(byte scale){
        ByteBuffer buffer = ByteBuffer.allocate(options.length+4);
        buffer.put(options);

        buffer.put(NOP)
                .put((byte)0x03)
                .put((byte)0x03)
                .put(_2ByteArrayBuild(scale));
        options=buffer.array();
    }

    public void setSACK(){
        ByteBuffer buffer = ByteBuffer.allocate(options.length+4);
        buffer.put(options);

        buffer.put(NOP)
                .put(NOP)
                .put((byte)0x04)
                .put((byte)0x02);
        options=buffer.array();
    }
    //——————————————————————————————

    private byte[] payload;

    public TCPPacket(int SrcPort, int DstPort, long SeqNum, long AckNum, byte[] Payload){

        //初始化
        srcPort=_2ByteArrayBuild(SrcPort);
        dstPort=_2ByteArrayBuild(DstPort);
        sequenceNum= _4ByteArrayBuild(SeqNum);
        acknowledgementNumber= _4ByteArrayBuild(AckNum);

        tcpHeaderLength=(byte)0x50;//默认设为20，有选项添加时在添加选项的方法添加

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
        // 将TCP头部长度左移8位（16 - 8）
        headerFlagsTemp |= tcpHeaderLength << 8;

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

    //判断指定端口是否可用
    public static boolean isPortAvailable(int portNumber) {
        if (portNumber > 65535 || portNumber < 0) return false;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //如果是第一次发包，填入的SequenceNum应当等于0；如果是客户端第一次发包，AckNum应当小于0。服务端第一次发包AckNum应当等于0；
    public byte[] build(String DstIP, int DstPort, long SequenceNum, long AckNum, byte[] Payload, int SrcPort) throws UnknownHostException {
        //依照老师的要求，手搓数据包

        //手搓TCP包头
        //从49153开始寻找可用端口直到找到
        int portTry = 49153;
        while (!isPortAvailable(portTry)) {
            portTry++;
        }
        //以字节数组形式构建srcPort
        byte[] srcPort = _2ByteArrayBuild(portTry);//源端口
        byte[] dstPort = _2ByteArrayBuild(DstPort);//目标端口

        //序列号，若第一次则随机生成，多次的话则+1
        byte[] sequenceNumber = null;
        if (SequenceNum == 0) {
            sequenceNumber = generateNewSequenceNumber();
        } else {
            sequenceNumber = _4ByteArrayBuild(SequenceNum + 1);
        }

        //AckNum，客户端第一次则为0，服务端第一次随机生成，多次则+1
        byte[] acknowledgementNumber = null;
        if (AckNum < 0) {
            acknowledgementNumber = _4ByteArrayBuild(0);
        }
        if (AckNum == 0) {
            acknowledgementNumber = generateNewSequenceNumber();
        }
        if (AckNum > 0) {
            acknowledgementNumber = _4ByteArrayBuild(AckNum + 1);
        }

        byte tcpHeaderLength = (byte) 0x80;//TCP头部长度，注意仅有4比特存储长度(因此最大为2^4=16字节)，后4比特中：前三比特为保留位，最后一个比特代表AccurateECN

        //以下9位为标志位，后续需要在参数内填入这些标志、实现修改
        boolean AccurateECN = false;
        boolean CongestionWindowReduced = false;
        boolean ECNEcho = false;
        boolean Urgent = false;
        boolean Acknowledgement = false;
        boolean Push = false;
        boolean Reset = false;
        boolean Syn = false;
        boolean Fin = false;

        // 将TCP头部长度左移12位（16 - 4）
        int headerFlagsTemp = 0;

        headerFlagsTemp |= tcpHeaderLength << 8;

        // 填充9个标志位
        headerFlagsTemp |= ((AccurateECN ? 1 : 0)) << 8;
        headerFlagsTemp |= (CongestionWindowReduced ? 1 : 0) << 7;
        headerFlagsTemp |= (ECNEcho ? 1 : 0) << 6;
        headerFlagsTemp |= (Urgent ? 1 : 0) << 5;
        headerFlagsTemp |= (Acknowledgement ? 1 : 0) << 4;
        headerFlagsTemp |= (Push ? 1 : 0) << 3;
        headerFlagsTemp |= (Reset ? 1 : 0) << 2;
        headerFlagsTemp |= (Syn ? 1 : 0) << 1;
        headerFlagsTemp |= (Fin ? 1 : 0);

        //将TCP头部长度和标志位都装入字节数组内
        byte[] headerLengthAndFlags = _2ByteArrayBuild(headerFlagsTemp);

        byte[] windowSize = _2ByteArrayBuild(2048);//暂且把窗口大小定为2048字节

        byte[] tcpChecksum = _2ByteArrayBuild(0x0000);//校验和，最后再进行计算

        byte[] urgentPointer = _2ByteArrayBuild(0x0000);//紧急指针，先设为0

        //各种选项(不一定需要)
        //MSS，4字节
        ByteBuffer mssTemp = ByteBuffer.allocate(4);//长度为4字节
        byte[] mssKindAndLength = _2ByteArrayBuild(0x0204);//类型定死，为02，长度为04；
        byte[] mssValue = _2ByteArrayBuild(1460);//本机网卡MTU为1460，硬编码？启动！
        mssTemp.put(mssKindAndLength).put(mssValue);

        byte[] mssResult = mssTemp.array();

        //SACK，2字节
        byte[] sackResult = _2ByteArrayBuild(0x0402);//类型，04；长度，02

        //Window scale，3字节
        ByteBuffer windowScaleTemp = ByteBuffer.allocate(3);
        byte[] windowScaleKindAndLength = _2ByteArrayBuild(0x0303);//类型定死，为03，长度为03；
        byte shiftCount = 0x08;//向左移的位数，即乘2的这个次方，此处暂且设为8，即2^8=256倍
        windowScaleTemp.put(windowScaleKindAndLength).put(shiftCount);

        byte[] windowScaleResult = windowScaleTemp.array();

        //NOP Example
        byte NOP = (byte) 0x01;//NOP占位符，用于将TCP头补齐为32位的整数倍(即4字节的整数倍)，补齐操作后续在计算校验和之前进行

        //进行补齐操作，先硬编码加3字节
        ByteBuffer paddingTemp = ByteBuffer.allocate(3);
        paddingTemp.put(NOP).put(NOP).put(NOP);
        byte[] paddingBytes = paddingTemp.array();

        //TCP头部长度计算

        //IP总长计算
        int ipLength = 20/*ip头长度*/ + 32/*TCP头长度*/ + Payload.length/*负载长度*/;
        totalLength = _2ByteArrayBuild(ipLength);

        //计算IP头的checksum值
        ByteBuffer ipHeadBuffer = ByteBuffer.allocate(20);
        ipHeadBuffer.put(versionAndHeaderLength)
                .put(serviceType).put(totalLength)
                .put(identification)
                .put(flagsAndFragmentOffset)
                .put(ttl)
                .put(protocol)
                .put(ipChecksum)
                .put(srcIP)
                .put(dstIP);
        ipChecksum = calculateChecksum(ipHeadBuffer.array());

        //计算TCP头的校验值

        ByteBuffer tcpHeadBuffer = ByteBuffer.allocate(/*伪首部*/12 + 32 + Payload.length);
        //伪首部
        tcpHeadBuffer.put(srcIP)
                .put(dstIP)
                .put((byte) 0x00)//全零占位
                .put((byte) 0x06)//tcp协议编号6
                .put(_2ByteArrayBuild(32 + Payload.length));//tcp实际报文和头部的长度和
        //tcp包
        tcpHeadBuffer.put(srcPort)
                .put(dstPort)
                .put(sequenceNumber)
                .put(acknowledgementNumber)
                .put(headerLengthAndFlags)
                .put(windowSize)
                .put(urgentPointer)
                .put(mssResult)
                .put(sackResult)
                .put(windowScaleResult)
                .put(paddingBytes)
                //负载（正文）
                .put(Payload);
        tcpChecksum = calculateChecksum(tcpHeadBuffer.array());

        //将所有内容合成一个字节数组（数据包）

        ByteBuffer buffer = ByteBuffer.allocate(14/*以太网头部长度*/ + ipLength);

        //以太包头
        buffer.put(new EthernetHead().autoBuild());

        //tcp包
        buffer.put(srcPort)
                .put(dstPort)
                .put(sequenceNumber)
                .put(acknowledgementNumber)
                .put(headerLengthAndFlags)
                .put(windowSize)
                .put(tcpChecksum)
                .put(urgentPointer)
                .put(mssResult)
                .put(sackResult)
                .put(windowScaleResult)
                .put(paddingBytes)
                //负载（正文）
                .put(Payload);

        return buffer.array();
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

    //checksum值的计算
    //https://stackoverflow.com/questions/4113890/how-to-calculate-the-internet-checksum-from-a-byte-in-java
    public byte[] calculateChecksum(byte[] inputData) {
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
}
