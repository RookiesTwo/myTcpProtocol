package top.rookiestwo;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import static top.rookiestwo.IPPacket.calculateChecksum;
import static top.rookiestwo.MyTcpProtocolMain._2ByteArrayBuild;
import static top.rookiestwo.MyTcpProtocolMain._4ByteArrayBuild;

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
    private byte[] windowSize;//窗口大小
    private byte[] checksum;//校验和，最后再进行计算
    private byte[] urgentPointer;//紧急指针，通常设为0
    private byte[] options;
    private byte NOP = (byte) 0x01;//Options的占位符
    private byte[] payload;
    //用于构建伪首部的IP信息
    private InetAddress srcIP;
    private InetAddress dstIP;
    public TCPPacket(String DstIP, int DstPort, int SrcPort, long SeqNum, long AckNum, byte[] Payload) throws UnknownHostException {
        //初始化
        srcIP = MyTcpProtocolMain.hostIP;
        dstIP = InetAddress.getByName(DstIP);

        srcPort = _2ByteArrayBuild(SrcPort);
        dstPort = _2ByteArrayBuild(DstPort);
        sequenceNum = _4ByteArrayBuild(SeqNum);
        acknowledgementNumber = _4ByteArrayBuild(AckNum);

        tcpHeaderLength = 20;//默认设为20，有选项添加时在添加选项的方法添加

        accurateECN = false;
        congestionWindowReduced = false;
        ecnEcho = false;
        urgent = false;
        acknowledgement = false;
        push = false;
        reset = false;
        syn = false;
        fin = false;

        this.setLengthAndFlags();

        windowSize = _2ByteArrayBuild(8192);//默认设为8192，不对劲以后再说
        checksum = _2ByteArrayBuild(0);//后续处理
        urgentPointer = _2ByteArrayBuild(0);//默认设为0

        options = new byte[0];

        payload = Payload;

        this.fillChecksum();
    }
    public TCPPacket(byte[] rawPacket) {
        srcPort = new byte[2];
        System.arraycopy(rawPacket, 34, srcPort, 0, 2);
        dstPort = new byte[2];
        System.arraycopy(rawPacket, 36, dstPort, 0, 2);
        sequenceNum = new byte[4];
        System.arraycopy(rawPacket, 38, sequenceNum, 0, 4);
        acknowledgementNumber = new byte[4];
        System.arraycopy(rawPacket, 42, acknowledgementNumber, 0, 4);
        LengthAndFlags = new byte[2];
        System.arraycopy(rawPacket, 46, LengthAndFlags, 0, 2);
        parseLengthAndFlags();
        //System.out.println(tcpHeaderLength);
        windowSize = new byte[2];
        System.arraycopy(rawPacket, 48, windowSize, 0, 2);
        checksum = new byte[2];
        System.arraycopy(rawPacket, 50, checksum, 0, 2);
        urgentPointer = new byte[2];
        System.arraycopy(rawPacket, 52, urgentPointer, 0, 2);
        options = new byte[tcpHeaderLength - 20];
        System.arraycopy(rawPacket, 54, options, 0, tcpHeaderLength - 20);
        byte[] ipTotalLength = new byte[2];
        System.arraycopy(rawPacket, 16, ipTotalLength, 0, 2);
        int temp = (ipTotalLength[0] << 8) + ipTotalLength[1];
        payload = new byte[temp - 20 - tcpHeaderLength];
        System.arraycopy(rawPacket, 34 + tcpHeaderLength, ipTotalLength, 0, temp - 20 - tcpHeaderLength);
    }

    public static void printBits(int number) {
        // int是32位的，我们从最高位开始检查
        for (int i = 31; i >= 0; i--) {
            // 使用移位和掩码来检查每个位
            int mask = 1 << i;  // 将1左移i位，创建一个只在第i位有1的掩码
            // 使用&操作符来确定第i位是否是1
            int result = (number & mask) != 0 ? 1 : 0;
            System.out.print(result);

            // 每隔4位添加一个空格，使输出更易于阅读
            if (i % 4 == 0) {
                System.out.print(" ");
            }
        }
        System.out.println();  // 换行
    }

    public boolean getAcknowledgement() {
        return acknowledgement;
    }

    public void setAcknowledgement(boolean acknowledgement) {
        this.acknowledgement = acknowledgement;
        this.setLengthAndFlags();
    }

    public long getAcknowledgementNumber() {
        long temp;
        temp=((long) (acknowledgementNumber[0]&0xFF)<<24)
                +((acknowledgementNumber[1]&0xFF)<<16)
                +((acknowledgementNumber[2]&0xFF)<<8)
                +(acknowledgementNumber[3]&0xFF);
        return temp;
    }

    public void setAcknowledgementNumber(long acknowledgementNumber) {
        this.acknowledgementNumber = _4ByteArrayBuild(acknowledgementNumber);
    }

    public long getSequenceNum() {
        long temp;
        temp = ((long) (sequenceNum[0] & 0xFF) << 24)
                + ((sequenceNum[1] & 0xFF) << 16)
                + ((sequenceNum[2] & 0xFF) << 8)
                + (sequenceNum[3] & 0xFF);
        return temp;
    }

    public void setSequenceNum(long sequenceNum) {
        this.sequenceNum = _4ByteArrayBuild(sequenceNum);
    }

    public byte[] getPayload() {
        return payload;
    }

    public boolean getSyn() {
        return syn;
    }

    public void setSyn(boolean syn) {
        this.syn = syn;
        this.setLengthAndFlags();
    }

    public boolean getFin() {
        return fin;
    }

    public void setFin(boolean fin) {
        this.fin = fin;
        this.setLengthAndFlags();
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = _2ByteArrayBuild(srcPort);
    }

    public void setDstPort(int dstPort) {
        this.dstPort = _2ByteArrayBuild(dstPort);
    }

    public void setTcpHeaderLength(int tcpHeaderLength) {

        if (tcpHeaderLength < 0 || tcpHeaderLength > 15) throw new NumberFormatException();
        this.tcpHeaderLength = tcpHeaderLength;
        this.setLengthAndFlags();
    }

    public void setAccurateECN(boolean accurateECN) {
        this.accurateECN = accurateECN;
        this.setLengthAndFlags();
    }

    public void setCongestionWindowReduced(boolean congestionWindowReduced) {
        this.congestionWindowReduced = congestionWindowReduced;
        this.setLengthAndFlags();
    }

    public void setEcnEcho(boolean ecnEcho) {
        this.ecnEcho = ecnEcho;
        this.setLengthAndFlags();
    }

    public void setUrgent(boolean urgent) {
        this.urgent = urgent;
        this.setLengthAndFlags();
    }

    public void setPush(boolean push) {
        this.push = push;
        this.setLengthAndFlags();
    }

    public void setReset(boolean reset) {
        this.reset = reset;
        this.setLengthAndFlags();
    }

    public void setWindowSize(byte[] windowSize) {
        this.windowSize = windowSize;
    }

    public void setUrgentPointer(byte[] urgentPointer) {
        this.urgentPointer = urgentPointer;
    }

    public void setMaxSegmentSize(int maxSegmentSize) {
        //保留options之前的内容
        ByteBuffer buffer = ByteBuffer.allocate(options.length + 4);
        buffer.put(options);
        //添加新字段
        buffer.put((byte) 0x02)
                .put((byte) 0x04)
                .put(_2ByteArrayBuild(maxSegmentSize));
        options = buffer.array();

        tcpHeaderLength += 4;
        this.setLengthAndFlags();
    }

    public void setWindowScale(byte scale) {
        ByteBuffer buffer = ByteBuffer.allocate(options.length + 4);
        buffer.put(options);

        buffer.put(NOP)
                .put((byte) 0x03)
                .put((byte) 0x03)
                .put(scale);
        options = buffer.array();

        tcpHeaderLength += 4;
        this.setLengthAndFlags();
    }

    public void setSACK() {
        ByteBuffer buffer = ByteBuffer.allocate(options.length + 4);
        buffer.put(options);

        buffer.put(NOP)
                .put(NOP)
                .put((byte) 0x04)
                .put((byte) 0x02);
        options = buffer.array();

        tcpHeaderLength += 4;
        this.setLengthAndFlags();
    }

    //将HeaderLength和9个标志位装进2字节数组里
    private void setLengthAndFlags() {
        int headerFlagsTemp = 0;
        // 将TCP头部长度左移12位（16 - 4）
        headerFlagsTemp |= ((tcpHeaderLength / 4) & 0x0000000F) << 12;

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
        //printBits(headerFlagsTemp);
        //printBits(tcpHeaderLength);
        LengthAndFlags = _2ByteArrayBuild(headerFlagsTemp);
    }

    private void parseLengthAndFlags() {
        tcpHeaderLength = ((LengthAndFlags[0] & 0xF0) >> 4) * 4;

        accurateECN = (LengthAndFlags[0] & 0x01) > 0;

        congestionWindowReduced = (LengthAndFlags[1] & 0x80) > 0;

        ecnEcho = (LengthAndFlags[1] & 0x40) > 0;

        urgent = (LengthAndFlags[1] & 0x20) > 0;

        acknowledgement = (LengthAndFlags[1] & 0x10) > 0;

        push = (LengthAndFlags[1] & 0x08) > 0;

        reset = (LengthAndFlags[1] & 0x04) > 0;

        syn = (LengthAndFlags[1] & 0x02) > 0;

        fin = (LengthAndFlags[1] & 0x01) > 0;
    }

    //获取整个TCP包
    public byte[] getTCPPacket() {
        ByteBuffer buffer = ByteBuffer.allocate(tcpHeaderLength + payload.length);
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

    public void fillChecksum() {
        checksum = _2ByteArrayBuild(0);
        ByteBuffer buffer = ByteBuffer.allocate(/*伪首部*/12 + tcpHeaderLength + payload.length);
        //伪首部
        buffer.put(srcIP.getAddress())
                .put(dstIP.getAddress())
                .put((byte) 0x00)//全零占位
                .put((byte) 0x06)//tcp协议编号6
                .put(_2ByteArrayBuild(tcpHeaderLength + payload.length));//tcp实际报文和头部的长度和
        buffer.put(this.getTCPPacket());
        checksum = calculateChecksum(buffer.array());
    }
}