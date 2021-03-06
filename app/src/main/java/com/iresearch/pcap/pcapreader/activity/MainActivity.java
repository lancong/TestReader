package com.iresearch.pcap.pcapreader.activity;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;

import com.iresearch.pcap.pcapreader.R;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

      Button mBtnReader = (Button) findViewById(R.id.btn_reader);
        mBtnReader.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(MainActivity.this,ReaderActivity.class));

            }
        });

        Button mBtnPcap = (Button) findViewById(R.id.btn_pcap);
        mBtnPcap.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(MainActivity.this,TcpDumpActivity.class));

            }
        });

    }



}
