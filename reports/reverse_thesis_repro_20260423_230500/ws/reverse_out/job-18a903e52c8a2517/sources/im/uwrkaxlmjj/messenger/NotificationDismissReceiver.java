package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/* JADX INFO: loaded from: classes2.dex */
public class NotificationDismissReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        int currentAccount = intent.getIntExtra("currentAccount", UserConfig.selectedAccount);
        long dialogId = intent.getLongExtra("dialogId", 0L);
        int date = intent.getIntExtra("messageDate", 0);
        if (dialogId == 0) {
            MessagesController.getNotificationsSettings(currentAccount).edit().putInt("dismissDate", date).commit();
            return;
        }
        MessagesController.getNotificationsSettings(currentAccount).edit().putInt("dismissDate" + dialogId, date).commit();
    }
}
