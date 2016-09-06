package com.iresearch.pcap.pcapreader.core;

import android.text.TextUtils;

import com.iresearch.pcap.pcapreader.core.command.CommandExecutor;
import com.iresearch.pcap.pcapreader.utils.LogUtils;
import com.iresearch.pcap.pcapreader.utils.Logger;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.application.HtmlParser;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Rtp;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;


/**
 * des   : 描述
 * author: wangyh
 * email : wyh_it@163.com
 * time  : 2016/8/29
 */
public class PacketReader {

    // Variable declarations for handling the settings.
//    private SharedPreferences settings = null;

    // ArrayList which will contain the parsed packets.
    private ArrayList<JPacket> packets = null;

    // Custom adapter for an ArrayList of JPacket.

    private int urlCount = 1;

    private String destinationIP;
    private String destinationPort;
    private String userAgent;
    private String host;
    private String requestUrl;
    private String requestMethod;
    private JSONObject json;
    private JSONArray ja;
    private int i = 0;
    private String packageName;





   /* public void onCreate() {
        packets = new ArrayList<JPacket>();

        // Parsing the packets form the .pcap file.
        getPackets();
        // Binding the ArrayAdapter with the view for each row of the ListView.

        new Thread(new Runnable() {
            @Override
            public void run() {
                for (int j = 0; j <  packets.size(); j++) {
                    getPacketInfo(packets);
                }
            }
        }).start();
    }*/



    public void Start(String filePath){
        packets = new ArrayList<JPacket>();

        // Parsing the packets form the .pcap file.
        getPackets(filePath);
        // Binding the ArrayAdapter with the view for each row of the ListView.
        new Thread(new Runnable() {
            @Override
            public void run() {
                for (int j = 0; j <  packets.size(); j++) {
                    getPacketInfo(packets);
                }
            }
        }).start();
    }


    /**
     * Opens the .pcap file which is defined in the preferences and parses all
     * the packets that it contains.<br>
     * The packet data is copied into the JPacket ArrayList.
     */
    private void getPackets(String filePath) {

        StringBuilder errbuf = new StringBuilder();

        // Opening the .pcap file.

//        String path = getSharedPreferences("config", Activity.MODE_PRIVATE).getString("pcapPath", "");

        Logger.d("当前使用的路径:              " + filePath);
        File file = new File(filePath);
        if (file.exists()){
            LogUtils.d("文件存在");
        }else {
            LogUtils.d("文件不存在");
        }

//        "/mnt/sdcard/2016_08_24_10_33_38.pcap"
        Pcap parser = Pcap.openOffline(filePath, errbuf);

        if (parser!=null){
            LogUtils.e("解析成功，开始解析");
            // Creating a handler for packet capture.
            JPacketHandler<String> handler = new JPacketHandler<String>() {

                // Defining the action that will be performed each time a packet is
                // read for the file.
                @Override
                public void nextPacket(JPacket packet, String user) {
                    packets.add(packet);

                }
            };

            parser.loop(-1, handler, null);
            parser.close();
        }else {
           LogUtils.d("解析失败，出现名称错误");
        }

    }

    /**
     * Custom ArrayAdapter for the Jnetpcap's JPacket class.<br>
     * Sets the view for each single packet that is stored in the ArrayList.
     */


    public void getPacketInfo(ArrayList<JPacket> packets) {
        JPacket p = packets.get(i);

        Ip4 ip4 = new Ip4();
        Ip6 ip6 = new Ip6();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        Icmp icmp = new Icmp();
        Http http = new Http();
        Rtp rtp = new Rtp();

        Logger.i("--------------------------------------------------------------------------");

        JCaptureHeader captureHeader = p.getCaptureHeader();

        if (p != null) {


            if (p.hasHeader(Ip4.ID)) {
                p.getHeader(ip4);
//                        src_network.setText(FormatUtils.ip(ip4.source()));
//                        dst_network.setText(FormatUtils.ip(ip4.destination()));
                destinationIP = FormatUtils.ip(ip4.destination());
                if (p.hasHeader(Tcp.ID)) {
                    p.getHeader(tcp);
//                            src_transport.setText(Integer.toString(tcp.source()));
//                            dst_transport.setText(Integer.toString(tcp.destination()));
                    destinationPort = Integer.toString(tcp.source());
                    if (p.hasHeader(Http.ID)) {
                        Http header = p.getHeader(http);

                        //获取url及userAgent
                        userAgent = header.fieldValue(Http.Request.User_Agent);
                        host = header.fieldValue(Http.Request.Host);
                        requestUrl = header.fieldValue(Http.Request.RequestUrl);
                        requestMethod = header.fieldValue(Http.Request.RequestMethod);


                        if (null != host) {
                            Logger.d("urlCount  :" + urlCount);
                            urlCount++;

                            long startTime = System.currentTimeMillis();
                            String uid = new CommandExecutor().getUid("cat /proc/net/tcp6", destinationPort);
                            long endTime = System.currentTimeMillis();
                            long costTime = endTime-startTime;
                            LogUtils.i("所需时间为:"+costTime);

                            if (!TextUtils.isEmpty(uid)){
                                LogUtils.d("111111");
                                packageName = new PackageInfos(MyApplication.getContext()).getPackage(uid);
                            }else {
                                LogUtils.d("22222222");
                                packageName = "";
                            }
                            getJson();
                            ja = new JSONArray();
                            ja.put(json);
                            ja.toString();
                            Logger.e("json数组" + ja.toString());
                        }

                    } else if (p.hasHeader(Rtp.ID)) {
                        p.getHeader(rtp);
//                                application_protocol.setText("RTP");
                    } else {
                    }
//                                application_protocol
//                                        .setText(getString(R.string.unknown));
                } else if (p.hasHeader(Udp.ID)) {
                    p.getHeader(udp);
//                            transport_protocol.setText("UDP");
//                            src_transport.setText(Integer.toString(udp.source()));
//                            dst_transport.setText(Integer.toString(udp.destination()));
                    if (p.hasHeader(Rtp.ID)) {
                        p.getHeader(rtp);
//                                application_protocol.setText("RTP");
                    }
                }
            } else if (p.hasHeader(Icmp.ID)) {
                p.getHeader(icmp);
//                        network_protocol.setText("ICMP");
//                        src_network.setText(getString(R.string.unknown));
//                        dst_network.setText(getString(R.string.unknown));
            } else if (p.hasHeader(Ip6.ID)) {
                p.getHeader(ip6);
//                        network_protocol.setText("IPv6");
//                        src_network.setText(FormatUtils.asStringIp6(ip6.source(),
//                                true));
//                        dst_network.setText(FormatUtils.asStringIp6(
//                                ip6.destination(), true));

                if (p.hasHeader(Tcp.ID)) {
                    p.getHeader(tcp);
//                            transport_protocol.setText("TCP");
//                            src_transport.setText(Integer.toString(tcp.source()));
//                            dst_transport.setText(Integer.toString(tcp.destination()));

                    if (p.hasHeader(Http.ID)) {
                        p.getHeader(http);
//                                application_protocol.setText("HTTP");
                        Html html = new Html();

                        HtmlParser htmlParser = new HtmlParser();


                    } else if (p.hasHeader(Rtp.ID)) {
                        p.getHeader(rtp);
//                                application_protocol.setText("RTP");
                    } else {
                    }
//                                application_protocol
//                                        .setText(getString(R.string.unknown));
                } else if (p.hasHeader(Udp.ID)) {
                    p.getHeader(udp);
//                            transport_protocol.setText("UDP");
//                            src_transport.setText(Integer.toString(udp.source()));
//                            dst_transport.setText(Integer.toString(udp.destination()));
                    if (p.hasHeader(Rtp.ID)) {
                        p.getHeader(rtp);
//                                application_protocol.setText("RTP");
                    }
                }
            }
        }
        i++;
    }


    private void getJson() {

        json = new JSONObject();
        long time = System.currentTimeMillis();
        //将数据存入json
        try {
            json.put("packagename", packageName);
            json.put("appname", "");
            json.put("appnamestore", "");
            json.put("appversion","");
            json.put("host", host);
            json.put("path", requestUrl);
            json.put("protocol", "");
            json.put("protocolversion", "");
            json.put("useragent", userAgent);
            json.put("method", requestMethod);
            json.put("ip", destinationIP);
            json.put("port", destinationPort);
            json.put("startmillistime", time);
            json.put("endmillistime", 0);
            Logger.d("getView: 当前json数据" + json.toString());
        } catch (JSONException e) {
            e.printStackTrace();

        }

    }



}
