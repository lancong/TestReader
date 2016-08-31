package com.iresearch.pcap.pcapreader.core.command;


import android.text.TextUtils;

import com.iresearch.pcap.pcapreader.utils.Logger;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;


public class CommandExecutor {

    private String uid;

    public static Process execCmd(String command) {
        return execCmd(new String[]{command}, true);
    }

    public static Process root() {
        return execCmd(null, false);
    }

    public static Process execCmd(String[] commands) {
        return execCmd(commands, false);
    }

    public static Process execCmd(String[] commands, boolean waitFor) {

        Process suProcess = null;
        try {
            suProcess = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(suProcess.getOutputStream());
            if (commands != null) {
                for (String cmd : commands) {
                    if (!TextUtils.isEmpty(cmd)) {
                        Logger.i("cmd命令 = " + cmd);
                        os.writeBytes(cmd + "\n");
                    }
                }
            }
            os.flush();
            os.writeBytes("exit\n");
            os.flush();

        } catch (IOException e) {
            e.printStackTrace();
        }


        return suProcess;
    }

    /**
     * 通过命令行获取uid
     */


    public String getUid(String command, String port) {

        Process mProcess;
        Runtime mRuntime = Runtime.getRuntime();
        uid = "";
        try {

//            port = Integer.toHexString(Integer.parseInt(port)).toUpperCase();//端口号16进制表现形式
            if (port.length() == 2) {
                port = "00" + port;
            } else if (port.length() == 3) {
                port = "0" + port;
            }
            Logger.d(command);
            mProcess = mRuntime.exec(command);
            BufferedReader mReader = new BufferedReader(new InputStreamReader(mProcess.getInputStream()));
            StringBuffer mRespBuff = new StringBuffer();

            String msg;
            while ((msg = mReader.readLine()) != null) {
                Logger.d(msg);
                String[] split = msg.split(" ");

                String HexPort = split[4].substring(split[4].length() - 4, split[4].length());
                if (!"ress".equals(HexPort)) {
                    String DecPort = Integer.parseInt(HexPort, 16) + "";//端口号10进制
//                    Logger.e(DecPort + "端口号比较" + port);
                    if (port.equals(DecPort)) {
                        uid = split[10];
                        if (!"".equals(uid)) {
                            Logger.e("getUid: 看看uid" + uid);

                        }
                    }


                }
            }
            mReader.close();

            Logger.d(mRespBuff.toString());

        } catch (IOException e) {
            e.printStackTrace();
        }

        return uid;
    }


}



