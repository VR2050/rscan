package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/* JADX INFO: loaded from: classes2.dex */
public class NotificationCallbackReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        ApplicationLoader.postInitApplication();
        int currentAccount = intent.getIntExtra("currentAccount", UserConfig.selectedAccount);
        long did = intent.getLongExtra("did", 777000L);
        byte[] data = intent.getByteArrayExtra("data");
        int mid = intent.getIntExtra("mid", 0);
        SendMessagesHelper.getInstance(currentAccount).sendNotificationCallback(did, mid, data);
    }
}
