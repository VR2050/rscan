package com.qunidayede.service;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/* loaded from: classes2.dex */
public class ServerManager extends BroadcastReceiver {

    /* renamed from: a */
    public Activity f10279a;

    /* renamed from: b */
    public Intent f10280b;

    public ServerManager(Activity activity) {
        this.f10279a = activity;
        this.f10280b = new Intent(activity, (Class<?>) CoreService.class);
    }

    /* renamed from: a */
    public static void m4566a(Context context, int i2, String str) {
        Intent intent = new Intent("com.xjbg.andserver.receiver");
        intent.putExtra("CMD_KEY", i2);
        intent.putExtra("MESSAGE_KEY", str);
        context.sendBroadcast(intent);
    }

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if ("com.xjbg.andserver.receiver".equals(intent.getAction())) {
            int intExtra = intent.getIntExtra("CMD_KEY", 0);
            if (intExtra == 1) {
                intent.getStringExtra("MESSAGE_KEY");
            } else {
                if (intExtra != 2) {
                    return;
                }
                intent.getStringExtra("MESSAGE_KEY");
            }
        }
    }
}
