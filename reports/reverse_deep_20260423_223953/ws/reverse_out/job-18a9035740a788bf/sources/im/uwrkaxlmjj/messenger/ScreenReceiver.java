package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;

/* JADX INFO: loaded from: classes2.dex */
public class ScreenReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction().equals("android.intent.action.SCREEN_OFF")) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("screen off");
            }
            ConnectionsManager.getInstance(UserConfig.selectedAccount).setAppPaused(true, true);
            ApplicationLoader.isScreenOn = false;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ScreenReceiver$NHpsvXQa_aKoiHc-cXJKzyYhqGI
                @Override // java.lang.Runnable
                public final void run() {
                    NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.screenchangenotify, 0);
                }
            });
            return;
        }
        if (intent.getAction().equals("android.intent.action.SCREEN_ON")) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("screen on");
            }
            ConnectionsManager.getInstance(UserConfig.selectedAccount).setAppPaused(false, true);
            ApplicationLoader.isScreenOn = true;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ScreenReceiver$BDTS78LtitRM2FAwaxq4tB_JOmA
                @Override // java.lang.Runnable
                public final void run() {
                    NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.screenchangenotify, 1);
                }
            });
        }
    }
}
