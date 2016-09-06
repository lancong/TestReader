package com.iresearch.pcap.pcapreader.core;

import android.app.Application;
import android.content.Context;

/**
 * des   : 描述
 * author: wangyh
 * email : wyh_it@163.com
 * time  : 2016/9/5
 */
public class MyApplication  extends  Application{
    private static Context mApplicationContext;

    @Override
    public void onCreate() {
        super.onCreate();
        mApplicationContext =getApplicationContext();
    }
    public  static  Context getContext(){
        return mApplicationContext;
    }
}

