package com.iresearch.pcap.pcapreader.core.command;


import android.content.Context;
import android.content.res.AssetManager;
import android.text.TextUtils;

import com.iresearch.pcap.pcapreader.core.PacketReader;
import com.iresearch.pcap.pcapreader.utils.FileUtils;
import com.iresearch.pcap.pcapreader.utils.ThreadPoolUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;


public class GeneralCommand {

    private static final String tag = GeneralCommand.class.getSimpleName();
    PacketReader packetReader = new PacketReader();
    private static String TCP_DUMP_NAME = "tcpdump";
    public ThreadPoolUtils threadPoolUtils;
    private String filePath;


    {
        threadPoolUtils = new ThreadPoolUtils(ThreadPoolUtils.Type.CachedThread, 6);
    }

    /**
     * 简单的请求root权限
     */
    public static void root() {
        CommandExecutor.root();
    }


    public static void chmod(String dir) {
        String command = "chmod 777 " + dir;
        CommandExecutor.execCmd(command);
    }

    /**
     * 手机抓包程序
     *
     * @param context
     */
    public void TcpDump(Context context) {
        chmod("data/local");

        File file = new File("data/local/", TCP_DUMP_NAME);

        if (file.exists()) {
            return;
        }

        InputStream is;
        OutputStream os;
        AssetManager am = context.getAssets();
        try {
            is = am.open(TCP_DUMP_NAME);
            os = new FileOutputStream(file);
            FileUtils.copyStream(is, os);

            FileUtils.closeSafely(is);
            FileUtils.closeSafely(os);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void startTcpDump(Context context, String filePath) {
        this.filePath = filePath;
        TcpDump(context);

        String[] commands = new String[7];
        commands[0] = "adb shell";
        commands[1] = "su";
        commands[4] = "chmod 777 /data/local/tcpdump";
        commands[5] = "cd /data/local";
        commands[6] = "./tcpdump -p -vv -s 0 -w " + filePath;
        CommandExecutor.execCmd(commands);

        stopTcpDump();//关闭抓包，生成.pcap文件


    }

    public void stopTcpDump() {

        String[] commands = new String[2];
        commands[0] = "adb shell";
        commands[1] = "ps|grep tcpdump|grep root|awk '{print $2}'";
        Process process = CommandExecutor.execCmd(commands);
        String result = parseInputStream(process.getInputStream());
        if (!TextUtils.isEmpty(result)) {
            String[] pids = result.split("\n");
            String[] killCmds = new String[pids.length];
            for (int i = 0; i < pids.length; ++i) {
                killCmds[i] = "kill -9 " + pids[i];
            }
            CommandExecutor.execCmd(killCmds);
        }
        parsePcap();

    }

    //解析pcap文件
    private void parsePcap() {

        threadPoolUtils.execute(new Runnable() {
            @Override
            public void run() {

                packetReader.Start(filePath);
            }
        });
    }

    private String parseInputStream(InputStream is) {
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);
        String line;
        StringBuilder sb = new StringBuilder();
        try {
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return sb.toString();
    }

}
