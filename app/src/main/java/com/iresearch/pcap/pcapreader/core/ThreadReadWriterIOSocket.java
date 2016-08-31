package com.iresearch.pcap.pcapreader.core;

import android.content.Context;

import com.iresearch.pcap.pcapreader.utils.Logger;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.Socket;


public class ThreadReadWriterIOSocket implements Runnable {
    private Socket client;
    private Context context;
    private String str="android测试";
    public ThreadReadWriterIOSocket(Context context, Socket client) {
        this.client = client;
        this.context = context;
    }

    @Override
    public void run() {
        Logger.d("开始发送数据");
        BufferedOutputStream out;
        BufferedInputStream in;
        try {
            /* PC端发来的数据msg */
            out = new BufferedOutputStream(client.getOutputStream());
            in = new BufferedInputStream(client.getInputStream());
            androidService.ioThreadFlag = true;
            try {
//                if (!client.isConnected()) {
//                }
                out.write(str.getBytes());
                out.flush();
            } catch (Exception e) {
                e.printStackTrace();
            }
            out.close();
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (client != null) {
                    Logger.d(Thread.currentThread().getName() + "---->" + "client.close()");
                    client.close();
                }
            } catch (IOException e) {
                Logger.e( Thread.currentThread().getName() + "---->" + "read write error333333");
                e.printStackTrace();
            }
        }
    }
}