package com.lljjcoder.style.citylist.Toast;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;

/* loaded from: classes2.dex */
public class ToastUtils {
    private static AlarmDailog alarmDialog;

    public static void showLongToast(Context context, String str) {
        if (alarmDialog != null) {
            alarmDialog = null;
        }
        AlarmDailog alarmDailog = new AlarmDailog(context);
        alarmDialog = alarmDailog;
        alarmDailog.setShowText(str);
        alarmDialog.show();
    }

    public static void showMomentToast(Activity activity, final Context context, final String str) {
        activity.runOnUiThread(new Runnable() { // from class: com.lljjcoder.style.citylist.Toast.ToastUtils.1
            @Override // java.lang.Runnable
            public void run() {
                if (ToastUtils.alarmDialog == null) {
                    AlarmDailog unused = ToastUtils.alarmDialog = new AlarmDailog(context);
                    ToastUtils.alarmDialog.setShowText(str);
                    ToastUtils.alarmDialog.setDuration(0);
                    ToastUtils.alarmDialog.show();
                } else {
                    ToastUtils.alarmDialog.setShowText(str);
                    ToastUtils.alarmDialog.show();
                }
                new Handler().postDelayed(new Runnable() { // from class: com.lljjcoder.style.citylist.Toast.ToastUtils.1.1
                    @Override // java.lang.Runnable
                    public void run() {
                        if (ToastUtils.alarmDialog != null) {
                            ToastUtils.alarmDialog.cancel();
                        }
                    }
                }, 2000L);
            }
        });
    }

    public static void showShortToast(Context context, String str) {
        if (alarmDialog != null) {
            alarmDialog = null;
        }
        AlarmDailog alarmDailog = new AlarmDailog(context);
        alarmDialog = alarmDailog;
        alarmDailog.setShowText(str);
        alarmDialog.setDuration(0);
        alarmDialog.show();
    }
}
