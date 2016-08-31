package com.iresearch.pcap.pcapreader.core;

import android.app.ActivityManager;
import android.content.Context;

import com.iresearch.pcap.pcapreader.utils.LogUtils;
import com.iresearch.pcap.pcapreader.utils.Logger;

import java.util.Iterator;
import java.util.List;

import static android.content.Context.ACTIVITY_SERVICE;


/**
 * des   : 描述
 * author: wangyh
 * email : wyh_it@163.com
 * time  : 2016/8/25
 */
public class PackageInfos {
    private Context context;

    public PackageInfos(Context context) {
        this.context = context;
    }

    public String getAppName(int pID) {
        String processName = "";
        ActivityManager am = (ActivityManager) context.getSystemService(ACTIVITY_SERVICE);
        List l = am.getRunningAppProcesses();
        Iterator i = l.iterator();
        android.content.pm.PackageManager pm = context.getPackageManager();
        while (i.hasNext()) {
            ActivityManager.RunningAppProcessInfo info = (ActivityManager.RunningAppProcessInfo) (i.next());
            try {
                if (info.pid == pID) {
//                    CharSequence c = pm.getApplicationLabel(pm.getApplicationInfo(info.processName, PackageInfos.GET_META_DATA));
                    //Log.d("Process", "Id: "+ info.pid +" ProcessName: "+ info.processName +"  Label: "+c.toString());
                    //processName = c.toString();
                    processName = info.processName;
                }
            } catch (Exception e) {
                //Log.d("Process", "Error>> :"+ e.toString());
            }
        }
        return processName;
    }


    public String getPackage(String uid) {
        int uid_1 = Integer.parseInt(uid);
        String p1 = null;
        try {

            String[] packagesForUid = context.getPackageManager().getPackagesForUid(uid_1);
            if (packagesForUid != null) {
                p1 = packagesForUid[0];
            }
            Logger.d("拿到的包名" + p1);

        } catch (Exception e) {
            LogUtils.d(e.toString());
        }

        return p1;

    }


}
