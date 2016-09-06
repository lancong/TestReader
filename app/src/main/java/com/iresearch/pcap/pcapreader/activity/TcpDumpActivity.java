package com.iresearch.pcap.pcapreader.activity;


import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import com.iresearch.pcap.pcapreader.R;
import com.iresearch.pcap.pcapreader.core.command.GeneralCommand;
import com.iresearch.pcap.pcapreader.utils.LogUtils;
import com.iresearch.pcap.pcapreader.utils.SpUtils;

import org.greenrobot.eventbus.EventBus;

import java.io.File;


public class TcpDumpActivity extends AppCompatActivity {
    private TextView tcpdump_text;

    private String savePath = Environment.getExternalStorageDirectory() + "/pcap" + File.separator;

    private long time;

    private GeneralCommand generalCommand;
    private boolean mFlag = true;
    private boolean isStartCapture = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_tcpdump);
        tcpdump_text = (TextView) findViewById(R.id.tcpdump_text);
        generalCommand = new GeneralCommand();
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.tcp_dump_start:
                if (!isStartCapture) {
                    isStartCapture = true;

                    new Thread() {
                        private String filePath;

                        public void run() {
                            mFlag = true;
                            while (mFlag) {
                                LogUtils.d("开始抓包");
                                time = System.currentTimeMillis();
                                filePath = savePath + time + ".pcap";
                                generalCommand.startTcpDump(getApplicationContext(), filePath);

                            }
                        }
                    }.start();

                } else {
                    Toast.makeText(this, "抓包中，请勿重新点击", Toast.LENGTH_SHORT).show();
                }

                break;
            case R.id.tcp_dump_stop:
                mFlag = false;
                isStartCapture = false;
                new SpUtils(this, "config").putString("pcapPath", savePath + time + ".pcap");
                tcpdump_text.setText("本次抓包文件保存在：\r\n" + savePath + time + ".pcap");
                LogUtils.d("抓包结束");

                break;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }
}
