package im.uwrkaxlmjj.messenger.voip;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/* JADX INFO: loaded from: classes2.dex */
public class VoIPActionsReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (VoIPBaseService.getSharedInstance() != null) {
            VoIPBaseService.getSharedInstance().handleNotificationAction(intent);
        }
    }
}
