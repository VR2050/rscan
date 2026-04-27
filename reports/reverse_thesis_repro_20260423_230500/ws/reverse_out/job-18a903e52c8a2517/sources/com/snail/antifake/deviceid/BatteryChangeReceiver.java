package com.snail.antifake.deviceid;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.core.app.NotificationCompat;

/* JADX INFO: loaded from: classes3.dex */
public class BatteryChangeReceiver extends BroadcastReceiver {
    private int mCurrentLevel;
    private boolean mIsCharging;

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        int status = intent.getIntExtra(NotificationCompat.CATEGORY_STATUS, 0);
        this.mCurrentLevel = intent.getIntExtra("level", 0);
        if (status != 1 && status != 2) {
            if (status == 3 || status == 4) {
                this.mIsCharging = false;
                return;
            } else if (status != 5) {
                return;
            }
        }
        this.mIsCharging = true;
    }

    public boolean isCharging() {
        return this.mIsCharging;
    }

    public int getCurrentLevel() {
        return this.mCurrentLevel;
    }
}
