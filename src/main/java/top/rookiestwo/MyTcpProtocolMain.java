package top.rookiestwo;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;

public class MyTcpProtocolMain {
    public static InetAddress usingDNS;
    public static InetAddress hostIP;
    public static MacAddress hostMAC;
    //硬编码网关MAC地址，我查了一圈，内网、外网。真的不好获取，可能其他语言好获取吧。
    //网关的MAC让jvm来干是真拿不到。我唯一能想到的办法就是开个进程跑ipconfig指令然后用正则表达式匹配。
    //但是这样写太丑陋了，我觉得还不如硬编码，或者直接让用户输入。
    //反正是北邮内网，还是直接硬编码吧。该MAC仅适用于北京邮电大学内网。
    //ps:本来用java写链路层我就觉得挺抽象的了（
    //This MAC address only works in BUPT network system.Please set your own gateway MAC.
    public static MacAddress gatewayMAC=MacAddress.getByName("10-4f-58-6c-0c-00");
    public static int requestTimes=0;//程序从启动开始的请求次数，每次构建包的时候应加1
    //网络配置部分
    public static int timeoutTime=1000;//超时时间，单位为毫秒
    public static PacketIOHandler PacketHandler;

    public static void main(String[] args) throws SocketException, UnknownHostException, PcapNativeException {
        //启动时初始化，获取当前网络环境信息
        Initialize();
        TCPPacketBuilder packetBuilder = new TCPPacketBuilder();
        System.out.println("Hello world!");
        //System.out.println(Arrays.toString(packetBuilder.generateNewSequenceNumber()));
    }

    private static void Initialize() throws UnknownHostException, SocketException, PcapNativeException {

        //获取本机IP从而获得MAC
        MyTcpProtocolMain.hostIP= InetAddress.getLocalHost();

        NetworkInterface networkInterface = NetworkInterface.getByInetAddress(MyTcpProtocolMain.hostIP);

        MyTcpProtocolMain.hostMAC= MacAddress.getByAddress(networkInterface.getHardwareAddress());

        MyTcpProtocolMain.usingDNS= InetAddress.getByName("1.1.1.1");

        PacketHandler=new PacketIOHandler();

        System.out.println();
        System.out.println("[Initial]当前本机IP为: "+MyTcpProtocolMain.hostIP.getHostAddress());
        System.out.println("[Initial]当前网卡MAC为: "+ MyTcpProtocolMain.hostMAC);
        System.out.println("[Initial]当前使用的DNS服务器IP为: "+ MyTcpProtocolMain.usingDNS.getHostAddress());
    }
}