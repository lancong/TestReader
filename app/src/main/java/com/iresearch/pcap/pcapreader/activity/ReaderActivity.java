package com.iresearch.pcap.pcapreader.activity;

import android.app.Activity;
import android.app.ListActivity;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import com.iresearch.pcap.pcapreader.R;
import com.iresearch.pcap.pcapreader.core.PackageInfos;
import com.iresearch.pcap.pcapreader.core.command.CommandExecutor;
import com.iresearch.pcap.pcapreader.utils.LogUtils;
import com.iresearch.pcap.pcapreader.utils.Logger;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
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

import java.util.ArrayList;


/**
 * des   : 描述
 * author: wangyh
 * email : wyh_it@163.com
 * time  : 2016/8/23
 */
public class   ReaderActivity extends ListActivity {

    // Variable declarations for handling the settings.
//    private SharedPreferences settings = null;

    // ArrayList which will contain the parsed packets.
    private ArrayList<JPacket> packets = null;

    // Custom adapter for an ArrayList of JPacket.
    private JPacketAdapter p_adapter;
    private int urlCount = 1;

    private String destinationIP;
    private String destinationPort;
    private String userAgent;
    private String host;
    private String requestUrl;
    private String requestMethod;
    private JSONObject json;
    private JSONArray ja;
    private String packageName;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_reader);

        packets = new ArrayList<JPacket>();


        // Parsing the packets form the .pcap file.
        getPackets();
        // Binding the ArrayAdapter with the view for each row of the ListView.
        p_adapter = new JPacketAdapter(this, R.layout.list_item, packets);

        // Binding the ArrayAdapter with the ListView.
        setListAdapter(p_adapter);

    }

    /**
     * Opens the .pcap file which is defined in the preferences and parses all
     * the packets that it contains.<br>
     * The packet data is copied into the JPacket ArrayList.
     */
    private void getPackets() {


        StringBuilder errbuf = new StringBuilder();

        // Opening the .pcap file.


        String path = getSharedPreferences("config", Activity.MODE_PRIVATE).getString("pcapPath", "");
        Logger.d("当前使用的路径" + path);
//        "/mnt/sdcard/2016_08_24_10_33_38.pcap"
        final Pcap parser = Pcap.openOffline(path, errbuf);


        // Creating a handler for packet capture.
        final JPacketHandler<String> handler = new JPacketHandler<String>() {

            // Defining the action that will be performed each time a packet is
            // read for the file.
            @Override
            public void nextPacket(JPacket packet, String user) {
                packets.add(packet);

            }
        };

        parser.loop(-1, handler, null);
        parser.close();
    }

    /**
     * Custom ArrayAdapter for the Jnetpcap's JPacket class.<br>
     * Sets the view for each single packet that is stored in the ArrayList.
     */
    private class JPacketAdapter extends ArrayAdapter<JPacket> {

        private ArrayList<JPacket> packets;


        public JPacketAdapter(Context context, int textViewResourceId,
                              ArrayList<JPacket> packets) {
            super(context, textViewResourceId, packets);
            this.packets = packets;

        }

        Ip4 ip4 = new Ip4();
        Ip6 ip6 = new Ip6();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        Icmp icmp = new Icmp();
        Http http = new Http();
        Rtp rtp = new Rtp();

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {

            View v = convertView;
            if (v == null) {
                LayoutInflater vi = (LayoutInflater) getSystemService(Context.LAYOUT_INFLATER_SERVICE);
                v = vi.inflate(R.layout.list_item, null);
            }
            JPacket p = packets.get(position);

            Logger.i("--------------------------------------------------------------------------");

            JCaptureHeader captureHeader = p.getCaptureHeader();

            if (p != null) {

                TextView network_protocol = (TextView) v
                        .findViewById(R.id.network_protocol_text);
                TextView src_network = (TextView) v
                        .findViewById(R.id.src_network_text);
                TextView dst_network = (TextView) v
                        .findViewById(R.id.dst_network_text);

                TextView transport_protocol = (TextView) v
                        .findViewById(R.id.transport_protocol_text);
                TextView src_transport = (TextView) v
                        .findViewById(R.id.src_transport_text);
                TextView dst_transport = (TextView) v
                        .findViewById(R.id.dst_transport_text);

                TextView application_protocol = (TextView) v
                        .findViewById(R.id.application_protocol_text);

                TextView packet_number = (TextView) v
                        .findViewById(R.id.packet_number_text);

                packet_number.setText(Integer.toString(position + 1));

                if (p.hasHeader(Ip4.ID)) {
                    p.getHeader(ip4);
                    network_protocol.setText("IPv4");
                    src_network.setText(FormatUtils.ip(ip4.source()));
                    dst_network.setText(FormatUtils.ip(ip4.destination()));
                    destinationIP = FormatUtils.ip(ip4.destination());
                    if (p.hasHeader(Tcp.ID)) {
                        p.getHeader(tcp);
                        transport_protocol.setText("TCP");
                        src_transport.setText(Integer.toString(tcp.source()));
                        dst_transport.setText(Integer.toString(tcp.destination()));
                        destinationPort = Integer.toString(tcp.source());
                        if (p.hasHeader(Http.ID)) {
                            Http header = p.getHeader(http);
                            application_protocol.setText("HTTP");

                            //获取url及userAgent
                            userAgent = header.fieldValue(Http.Request.User_Agent);
                            host = header.fieldValue(Http.Request.Host);
                            requestUrl = header.fieldValue(Http.Request.RequestUrl);
                            requestMethod = header.fieldValue(Http.Request.RequestMethod);



                            if (TextUtils.isEmpty(host)) {
                                Logger.d("urlCount  :" + urlCount);
                                urlCount++;

                                long startTime = System.currentTimeMillis();
                                String uid = new CommandExecutor().getUid("cat /proc/net/tcp6", destinationPort);
                                long endTime = System.currentTimeMillis();
                                long costTime = endTime-startTime;
                                LogUtils.i("所需时间为:"+costTime);
                                if (!TextUtils.isEmpty(uid)){
                                    LogUtils.d("111111");
                                    packageName = new PackageInfos(ReaderActivity.this).getPackage(uid);
                                }else {
                                    LogUtils.d("22222222");
                                    packageName = "";
                                }
                                getJson();
                                ja = new JSONArray();
                                ja.put(json);

                                Logger.e("json数组" +ja);
                            }


                        } else if (p.hasHeader(Rtp.ID)) {
                            p.getHeader(rtp);
                            application_protocol.setText("RTP");
                        } else
                            application_protocol
                                    .setText(getString(R.string.unknown));
                    } else if (p.hasHeader(Udp.ID)) {
                        p.getHeader(udp);
                        transport_protocol.setText("UDP");
                        src_transport.setText(Integer.toString(udp.source()));
                        dst_transport.setText(Integer.toString(udp.destination()));
                        if (p.hasHeader(Rtp.ID)) {
                            p.getHeader(rtp);
                            application_protocol.setText("RTP");
                        }
                    }
                } else if (p.hasHeader(Icmp.ID)) {
                    p.getHeader(icmp);
                    network_protocol.setText("ICMP");
                    src_network.setText(getString(R.string.unknown));
                    dst_network.setText(getString(R.string.unknown));
                } else if (p.hasHeader(Ip6.ID)) {
                    p.getHeader(ip6);
                    network_protocol.setText("IPv6");
                    src_network.setText(FormatUtils.asStringIp6(ip6.source(),
                            true));
                    dst_network.setText(FormatUtils.asStringIp6(
                            ip6.destination(), true));

                    if (p.hasHeader(Tcp.ID)) {
                        p.getHeader(tcp);
                        transport_protocol.setText("TCP");
                        src_transport.setText(Integer.toString(tcp.source()));
                        dst_transport.setText(Integer.toString(tcp.destination()));

                        if (p.hasHeader(Http.ID)) {
                            p.getHeader(http);
                            application_protocol.setText("HTTP");


                        } else if (p.hasHeader(Rtp.ID)) {
                            p.getHeader(rtp);
                            application_protocol.setText("RTP");
                        } else
                            application_protocol
                                    .setText(getString(R.string.unknown));
                    } else if (p.hasHeader(Udp.ID)) {
                        p.getHeader(udp);
                        transport_protocol.setText("UDP");
                        src_transport.setText(Integer.toString(udp.source()));
                        dst_transport.setText(Integer.toString(udp.destination()));
                        if (p.hasHeader(Rtp.ID)) {
                            p.getHeader(rtp);
                            application_protocol.setText("RTP");
                        }
                    }
                }
            }
            return v;
        }
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
