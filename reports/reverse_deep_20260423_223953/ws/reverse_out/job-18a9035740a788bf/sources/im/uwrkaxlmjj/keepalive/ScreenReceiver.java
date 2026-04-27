package im.uwrkaxlmjj.keepalive;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;

/* JADX INFO: loaded from: classes2.dex */
public class ScreenReceiver extends BroadcastReceiver {
    private Handler mHandler = new Handler(Looper.getMainLooper());
    private CheckTopTask mCheckTopTask = new CheckTopTask(ApplicationLoader.applicationContext);

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        try {
            if ("android.intent.action.SCREEN_OFF".equals(action)) {
                CheckTopTask.startForeground(context);
                if (this.mHandler != null) {
                    this.mHandler.postDelayed(this.mCheckTopTask, 3000L);
                    return;
                }
                return;
            }
            if ("android.intent.action.USER_PRESENT".equals(action) || "android.intent.action.SCREEN_ON".equals(action)) {
                OnePxActivity onePxActivity = OnePxActivity.instance != null ? OnePxActivity.instance.get() : null;
                if (onePxActivity != null) {
                    onePxActivity.finishSelf();
                }
                if (this.mHandler != null) {
                    this.mHandler.removeCallbacks(this.mCheckTopTask);
                }
            }
        } catch (Throwable e) {
            FileLog.e("ScreenReceiver onReceive error:" + e.toString());
        }
    }
}
