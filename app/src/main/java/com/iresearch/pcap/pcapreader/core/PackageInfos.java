package com.iresearch.pcap.pcapreader.core;

import android.content.Context;

import com.iresearch.pcap.pcapreader.utils.LogUtils;
import com.iresearch.pcap.pcapreader.utils.Logger;


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
