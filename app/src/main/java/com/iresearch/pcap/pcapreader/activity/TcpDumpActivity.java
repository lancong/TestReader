package com.iresearch.pcap.pcapreader.activity;


import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;

import com.iresearch.pcap.pcapreader.R;
import com.iresearch.pcap.pcapreader.core.command.GeneralCommand;
import com.iresearch.pcap.pcapreader.utils.SpUtils;

import java.io.File;


public class TcpDumpActivity extends AppCompatActivity {
    private TextView tcpdump_text;

    private String savePath = Environment.getExternalStorageDirectory() + File.separator;

    private long time;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_tcpdump);
        tcpdump_text = (TextView) findViewById(R.id.tcpdump_text);


    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.tcp_dump_start:
                time = System.currentTimeMillis();

                new Thread() {
                    public void run() {



                        GeneralCommand.startTcpDump(getApplicationContext(), savePath
                                + time + ".pcap");

                    }
                }.start();
                break;
            case R.id.tcp_dump_stop:
                new Thread() {
                    public void run() {
                        GeneralCommand.stopTcpDump();
                    }
                }.start();
                new SpUtils(this,"config").putString("pcapPath",savePath + time + ".pcap");
                tcpdump_text.setText("本次抓包文件保存在：\r\n" + savePath + time + ".pcap");
                startActivity(new Intent(this, ReaderActivity.class));
                finish();
                break;
        }
    }
}
