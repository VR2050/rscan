package org.webrtc.mozi;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;

/* JADX INFO: loaded from: classes3.dex */
public class AndroidScreenCapService extends Service {
    private static final String TAG = "JavaScreenCapturer";

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return new Binder();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        Logging.d(TAG, "onStartCommand ");
        startforeground();
        super.onStartCommand(intent, flags, startId);
        return 2;
    }

    @Override // android.app.Service
    public void onDestroy() {
        stopforeground();
        super.onDestroy();
    }

    private void startforeground() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel("9989", "myChannel", 0);
            channel.setLightColor(-16776961);
            channel.setLockscreenVisibility(0);
            NotificationManager manager = (NotificationManager) getSystemService("notification");
            if (manager != null) {
                manager.createNotificationChannel(channel);
                Notification notification = new Notification.Builder(getApplicationContext(), "9989").setOngoing(true).setCategory(NotificationCompat.CATEGORY_SERVICE).build();
                if (Build.VERSION.SDK_INT >= 29) {
                    startForeground(110, notification, 32);
                } else {
                    startForeground(110, notification);
                }
            }
        }
    }

    private void stopforeground() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(1);
        } else {
            stopForeground(true);
        }
    }
}
