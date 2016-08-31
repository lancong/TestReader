package com.iresearch.pcap.pcapreader.core;


import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;

import com.iresearch.pcap.pcapreader.utils.Logger;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class androidService extends Service {

    private static Boolean mainThreadFlag = true;
    public static Boolean ioThreadFlag = true;
    ServerSocket serverSocket = null;
    final int SERVER_PORT = 10087;

    private sysBroadcastReceiver sysBR;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Logger.d("androidService--->onCreate()");
        /* 创建内部类sysBroadcastReceiver 并注册registerReceiver */
        sysRegisterReceiver();

    }

    private void doListen() {
        serverSocket = null;
        try {
            Log.d("chl", "doListen()");
            try {
                serverSocket = new ServerSocket(SERVER_PORT);
            }catch (Exception e){
                Log.d("chl", " Message "+e.getMessage());
                Toast.makeText(getApplicationContext(),e.getMessage(),Toast.LENGTH_LONG).show();
            }
            Log.d("chl", "doListen() 2");
            while (mainThreadFlag) {
                Log.d("chl", "doListen() 4");
                Socket socket = serverSocket.accept();
                Log.d("chl", "doListen() 3");
                new Thread(new ThreadReadWriterIOSocket(this, socket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /* 创建内部类sysBroadcastReceiver 并注册registerReceiver */
    private void sysRegisterReceiver() {
        Logger.d( Thread.currentThread().getName() + "---->" + "sysRegisterReceiver");
        sysBR = new sysBroadcastReceiver();
		/* 注册BroadcastReceiver */
        IntentFilter filter1 = new IntentFilter();
		/* 新的应用程序被安装到了设备上的广播 */
        filter1.addAction("android.intent.action.PACKAGE_ADDED");
        filter1.addDataScheme("package");
        filter1.addAction("android.intent.action.PACKAGE_REMOVED");
        filter1.addDataScheme("package");
        registerReceiver(sysBR, filter1);
    }

    /* 内部类：BroadcastReceiver 用于接收系统事件 */
    private class sysBroadcastReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equalsIgnoreCase("android.intent.action.PACKAGE_ADDED")) {
                // ReadInstalledAPP();
            } else if (action.equalsIgnoreCase("android.intent.action.PACKAGE_REMOVED")) {
                // ReadInstalledAPP();
            }
            Logger.d( Thread.currentThread().getName() + "---->" + "sysBroadcastReceiver onReceive");
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Logger.d("androidService----->onStartCommand()");
        mainThreadFlag = true;
        new Thread() {
            public void run() {
                doListen();
            }
        }.start();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        // 关闭线程
        mainThreadFlag = false;
        ioThreadFlag = false;
        // 关闭服务器
        try {
            Logger.d( Thread.currentThread().getName() + "---->" + "serverSocket.close()");
            if (serverSocket != null) serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Logger.d( Thread.currentThread().getName() + "---->" + "**************** onDestroy****************");
    }

}
