package im.uwrkaxlmjj.keepalive;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.os.Process;
import im.uwrkaxlmjj.messenger.FileLog;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
class CheckTopTask implements Runnable {
    private Context context;

    CheckTopTask(Context context) {
        this.context = context;
    }

    static void startForeground(Context context) {
        try {
            Intent intent = new Intent(context, (Class<?>) OnePxActivity.class);
            intent.addFlags(805306368);
            context.startActivity(intent);
        } catch (Exception e) {
            FileLog.e("CheckTopTask startForeground error:" + e.toString());
        }
    }

    @Override // java.lang.Runnable
    public void run() {
        boolean foreground = isForeground(this.context);
        if (!foreground) {
            startForeground(this.context);
        }
    }

    private boolean isForeground(Context context) {
        try {
            ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
            List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = activityManager.getRunningAppProcesses();
            if (runningAppProcesses != null) {
                int myPid = Process.myPid();
                for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
                    if (runningAppProcessInfo.pid == myPid) {
                        return runningAppProcessInfo.importance <= 100;
                    }
                }
            }
        } catch (Exception e) {
            FileLog.e("CheckTopTask isForeground error:" + e.toString());
        }
        return false;
    }
}
