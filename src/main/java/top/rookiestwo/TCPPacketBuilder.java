package top.rookiestwo;

import org.pcap4j.packet.namednumber.Port;
import org.pcap4j.util.MacAddress;

import java.net.*;
import java.nio.ByteBuffer;
import java.util.Random;

public class TCPPacketBuilder {

    MacAddress hostMAC;
    InetAddress hostIP=null;

    public TCPPacketBuilder() throws UnknownHostException, SocketException {
        //获取本机IP从而获得MAC
        hostIP=MyTcpProtocolMain.hostIP;
        hostMAC=MyTcpProtocolMain.hostMAC;
    }

    //如果是第一次发包，填入的SequenceNum应当等于0；如果是客户端第一次发包，AckNum应当小于0。服务端第一次发包AckNum应当等于0；
    public byte[] build(String DstIP,long SequenceNum,long AckNum,byte[] Payload,int DstPort) throws UnknownHostException {
        //依照老师的要求，手搓数据包

        // 第一步，获取MAC字节码
        //构建以太网header
        byte[] gatewayBytes=MyTcpProtocolMain.gatewayMAC.getAddress();
        byte[] hostBytes=hostMAC.getAddress();
        //由于是ipv4
        byte[] etherType=_2ByteArrayBuild(0x0800);

        //手搓ip数据包包头
        byte versionAndHeaderLength = (byte) 0x45; // 版本和头部长度
        byte serviceType = (byte) 0x00; // 服务类型
        byte[] totalLength; // 总长度，后边赋值

        // 创建一个随机数生成器
        Random random = new Random();

        // 生成一个随机的Identification值（16位）
        int identificationRandom = random.nextInt(65535);
        byte[] identification = _2ByteArrayBuild(identificationRandom); // 有可能要分片，分片后续再处理- - - - - - -

        byte[] flagsAndFragmentOffset = _2ByteArrayBuild(0x4000); // 标志和片偏移,不偏移，不分片因此后两位为00，前两位为40
        byte ttl = (byte) 0x80; // TTL,设定为128次
        byte protocol = (byte) 0x06; // 协议,TCP为6,即0x06
        byte[] ipChecksum = _2ByteArrayBuild(0x0000); // 校验和，后续进行验证
        byte[] srcIP= Inet4Address.getByName(hostIP.getHostAddress()).getAddress();//本机IP
        byte[] dstIP=Inet4Address.getByName(DstIP).getAddress();//目标hostIP

        //手搓TCP包头
        //从49153开始寻找可用端口直到找到
        int portTry=49153;
        while(!isPortAvailable(portTry)){
            portTry++;
        }
        //以字节数组形式构建srcPort
        byte[] srcPort=_2ByteArrayBuild(portTry);//源端口
        byte[] dstPort=_2ByteArrayBuild(DstPort);//目标端口

        //序列号，若第一次则随机生成，多次的话则+1
        byte[] sequenceNumber=null;
        if(SequenceNum==0){
            sequenceNumber=generateNewSequenceNumber();
        }
        else{
            sequenceNumber=longLowTo4Bytes(SequenceNum+1);
        }

        //AckNum，客户端第一次则为0，服务端第一次随机生成，多次则+1
        byte[] acknowledgementNumber=null;
        if(AckNum<0){
            acknowledgementNumber=longLowTo4Bytes(0);
        }
        if(AckNum==0){
            acknowledgementNumber=generateNewSequenceNumber();
        }
        if(AckNum>0){
            acknowledgementNumber=longLowTo4Bytes(AckNum+1);
        }

        byte tcpHeaderLength=(byte) 0x80;//TCP头部长度，注意仅有4比特存储长度(因此最大为2^4=16字节)，后4比特中：前三比特为保留位，最后一个比特代表AccurateECN

        //以下9位为标志位，后续需要在参数内填入这些标志、实现修改
        boolean AccurateECN=false;
        boolean CongestionWindowReduced=false;
        boolean ECNEcho=false;
        boolean Urgent=false;
        boolean Acknowledgement=false;
        boolean Push=false;
        boolean Reset=false;
        boolean Syn=false;
        boolean Fin=false;

        // 将TCP头部长度左移12位（16 - 4）
        int headerFlagsTemp = 0;

        headerFlagsTemp |= (tcpHeaderLength & 0xFFFF0000) << 12;

        // 填充9个标志位
        headerFlagsTemp |= ((AccurateECN ? 1: 0 )) << 8;
        headerFlagsTemp |= (CongestionWindowReduced ? 1 : 0) << 7;
        headerFlagsTemp |= (ECNEcho ? 1 : 0) << 6;
        headerFlagsTemp |= (Urgent ? 1 : 0) << 5;
        headerFlagsTemp |= (Acknowledgement ? 1 : 0) << 4;
        headerFlagsTemp |= (Push ? 1 : 0) << 3;
        headerFlagsTemp |= (Reset ? 1 : 0) << 2;
        headerFlagsTemp |= (Syn ? 1 : 0) << 1;
        headerFlagsTemp |= (Fin ? 1 : 0);

        //将TCP头部长度和标志位都装入字节数组内
        byte[] headerLengthAndFlags=_2ByteArrayBuild(headerFlagsTemp);

        byte[] windowSize=_2ByteArrayBuild(2048);//暂且把窗口大小定为2048字节

        byte[] tcpChecksum=_2ByteArrayBuild(0x0000);//校验和，最后再进行计算

        byte[] urgentPointer=_2ByteArrayBuild(0x0000);//紧急指针，先设为0

        //各种选项(不一定需要)
        //MSS，4字节
        ByteBuffer mssTemp=ByteBuffer.allocate(4);//长度为4字节
        byte[] mssKindAndLength=_2ByteArrayBuild(0x0204);//类型定死，为02，长度为04；
        byte[] mssValue=_2ByteArrayBuild(1460);//本机网卡MTU为1460，硬编码？启动！
        mssTemp.put(mssKindAndLength).put(mssValue);

        byte[] mssResult=mssTemp.array();

        //SACK，2字节
        byte[] sackResult=_2ByteArrayBuild(0x0402);//类型，04；长度，02

        //Window scale，3字节
        ByteBuffer windowScaleTemp=ByteBuffer.allocate(3);
        byte[] windowScaleKindAndLength=_2ByteArrayBuild(0x0303);//类型定死，为03，长度为03；
        byte shiftCount=0x08;//向左移的位数，即乘2的这个次方，此处暂且设为8，即2^8=256倍
        windowScaleTemp.put(windowScaleKindAndLength).put(shiftCount);

        byte[] windowScaleResult=windowScaleTemp.array();

        //NOP Example
        byte NOP=(byte)0x01;//NOP占位符，用于将TCP头补齐为32位的整数倍(即4字节的整数倍)，补齐操作后续在计算校验和之前进行

        //进行补齐操作，先硬编码加3字节
        ByteBuffer paddingTemp=ByteBuffer.allocate(3);
        paddingTemp.put(NOP).put(NOP).put(NOP);
        byte[] paddingBytes= paddingTemp.array();

        //TCP头部长度计算

        //IP总长计算
        int ipLength=(versionAndHeaderLength & 0x0F)*4/*ip头长度*/ + tcpHeaderLength/*TCP头长度*/+ Payload.length/*负载长度*/;
        totalLength=_2ByteArrayBuild(ipLength);

        //计算IP头的checksum值
        ByteBuffer ipHeadBuffer=ByteBuffer.allocate((versionAndHeaderLength & 0x0F)*4);
        ipHeadBuffer.put(versionAndHeaderLength)
                .put(serviceType).put(totalLength)
                .put(identification)
                .put(flagsAndFragmentOffset)
                .put(ttl)
                .put(protocol)
                .put(ipChecksum)
                .put(srcIP)
                .put(dstIP);
        ipChecksum=calculateChecksum(ipHeadBuffer.array());

        //计算TCP头的校验值

        ByteBuffer tcpHeadBuffer=ByteBuffer.allocate(/*伪首部*/12+tcpHeaderLength+Payload.length);
        //伪首部
        tcpHeadBuffer.put(srcIP)
                .put(dstIP)
                .put((byte)0x00)//全零占位
                .put((byte)0x06)//tcp协议编号6
                .put(_2ByteArrayBuild(tcpHeaderLength+Payload.length));//tcp实际报文和头部的长度和
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
        tcpChecksum=calculateChecksum(tcpHeadBuffer.array());

        //将所有内容合成一个字节数组（数据包）

        ByteBuffer buffer=ByteBuffer.allocate(14/*以太网头部长度*/+ipLength);

        //以太包头
        buffer.put(gatewayBytes)
                .put(hostBytes)
                .put(etherType);

        //ip包头
        buffer.put(versionAndHeaderLength)
                .put(serviceType).put(totalLength)
                .put(identification)
                .put(flagsAndFragmentOffset)
                .put(ttl)
                .put(protocol)
                .put(ipChecksum)
                .put(srcIP)
                .put(dstIP);

        //tcp包
        tcpHeadBuffer.put(srcPort)
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

    //根据输入的int值,将其转为能存入两个字节的字节数组
    public byte[] _2ByteArrayBuild(int input){
        byte[] temp=new byte[2];
        temp[0] = (byte) ((input >> 8) & 0xFF);
        temp[1] = (byte) (input & 0xFF);
        return temp;
    }

    //随机生成一个全新的sequenceNumber，并装进byte数组
    private byte[] generateNewSequenceNumber(){
        Random rand = new Random();
        long sequenceNumber = 0;
        long quarter = 0xFFFFFFFFL / 4;
        while(sequenceNumber<quarter||sequenceNumber>quarter*3){
            sequenceNumber = rand.nextLong() & 0xFFFFFFFFL;
        }
        return longLowTo4Bytes(sequenceNumber);
    }

    //取long的最低4字节塞进字节数组
    private byte[] longLowTo4Bytes(long inputNum){
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(inputNum);
        byte[] array = buffer.array();
        // We only need the last 4 bytes for a 32-bit number
        byte[] fourBytes = new byte[4];
        System.arraycopy(array, 4, fourBytes, 0, 4);
        return fourBytes;
    }

    //判断指定端口是否可用
    public static boolean isPortAvailable(int portNumber) {
        if(portNumber>65535||portNumber<0)return false;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            return true;
        } catch (Exception e) {
            return false;
        }
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
        return _2ByteArrayBuild((int)sum);
    }
}
