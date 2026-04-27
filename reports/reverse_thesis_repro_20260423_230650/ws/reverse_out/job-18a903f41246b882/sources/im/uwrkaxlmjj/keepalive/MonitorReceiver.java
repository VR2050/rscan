package im.uwrkaxlmjj.keepalive;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import im.uwrkaxlmjj.messenger.FileLog;

/* JADX INFO: loaded from: classes2.dex */
public class MonitorReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        FileLog.d("MonitorReceiver onReceive(): intent: " + intent.toUri(0));
        try {
            Intent target = new Intent(context, (Class<?>) DaemonService.class);
            context.startService(target);
        } catch (Throwable e) {
            FileLog.e("MonitorReceiver onReceive error:" + e.toString());
        }
    }
}
