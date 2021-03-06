package com.iresearch.pcap.pcapreader.core;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import com.iresearch.pcap.pcapreader.utils.Logger;

public class ServiceBroadcastReceiver extends BroadcastReceiver {

	private static String START_ACTION = "NotifyServiceStart";
	private static String STOP_ACTION = "NotifyServiceStop";

	@Override
	public void onReceive(Context context, Intent intent) {
		Logger.d( Thread.currentThread().getName() + "---->"
                + "ServiceBroadcastReceiver onReceive");  
  
        String action = intent.getAction();  
        if (START_ACTION.equalsIgnoreCase(action)) {  
            context.startService(new Intent(context, androidService.class));  
  
            Logger.d( Thread.currentThread().getName() + "---->"
                    + "ServiceBroadcastReceiver onReceive start end");  
        } else if (STOP_ACTION.equalsIgnoreCase(action)) {  
            context.stopService(new Intent(context, androidService.class));  
            Logger.d( Thread.currentThread().getName() + "---->"
                    + "ServiceBroadcastReceiver onReceive stop end");  
        }  
	}

}
