package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/* JADX INFO: loaded from: classes2.dex */
public class PopupReplyReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        ApplicationLoader.postInitApplication();
        NotificationsController.getInstance(intent.getIntExtra("currentAccount", UserConfig.selectedAccount)).forceShowPopupForReply();
    }
}
