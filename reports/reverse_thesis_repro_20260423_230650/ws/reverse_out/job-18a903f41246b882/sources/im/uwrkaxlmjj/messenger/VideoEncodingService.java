package im.uwrkaxlmjj.messenger;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import im.uwrkaxlmjj.messenger.NotificationCenter;

/* JADX INFO: loaded from: classes2.dex */
public class VideoEncodingService extends Service implements NotificationCenter.NotificationCenterDelegate {
    private NotificationCompat.Builder builder;
    private int currentAccount;
    private int currentProgress;
    private String path;

    public VideoEncodingService() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.stopEncodingService);
    }

    @Override // android.app.Service
    public IBinder onBind(Intent arg2) {
        return null;
    }

    @Override // android.app.Service
    public void onDestroy() {
        super.onDestroy();
        try {
            stopForeground(true);
        } catch (Throwable th) {
        }
        NotificationManagerCompat.from(ApplicationLoader.applicationContext).cancel(4);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.stopEncodingService);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileUploadProgressChanged);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("destroy video service");
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        String str;
        if (id == NotificationCenter.FileUploadProgressChanged) {
            String fileName = (String) args[0];
            if (account == this.currentAccount && (str = this.path) != null && str.equals(fileName)) {
                Float progress = (Float) args[1];
                int iFloatValue = (int) (progress.floatValue() * 100.0f);
                this.currentProgress = iFloatValue;
                this.builder.setProgress(100, iFloatValue, iFloatValue == 0);
                try {
                    NotificationManagerCompat.from(ApplicationLoader.applicationContext).notify(4, this.builder.build());
                    return;
                } catch (Throwable e) {
                    FileLog.e(e);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.stopEncodingService) {
            String filepath = (String) args[0];
            int account2 = ((Integer) args[1]).intValue();
            if (account2 == this.currentAccount) {
                if (filepath == null || filepath.equals(this.path)) {
                    stopSelf();
                }
            }
        }
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        this.path = intent.getStringExtra("path");
        int oldAccount = this.currentAccount;
        int intExtra = intent.getIntExtra("currentAccount", UserConfig.selectedAccount);
        this.currentAccount = intExtra;
        if (oldAccount != intExtra) {
            NotificationCenter.getInstance(oldAccount).removeObserver(this, NotificationCenter.FileUploadProgressChanged);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileUploadProgressChanged);
        }
        boolean isGif = intent.getBooleanExtra("gif", false);
        if (this.path == null) {
            stopSelf();
            return 2;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("start video service");
        }
        if (this.builder == null) {
            NotificationsController.checkOtherNotificationsChannel();
            NotificationCompat.Builder builder = new NotificationCompat.Builder(ApplicationLoader.applicationContext);
            this.builder = builder;
            builder.setSmallIcon(android.R.drawable.stat_sys_upload);
            this.builder.setWhen(System.currentTimeMillis());
            this.builder.setChannelId(NotificationsController.OTHER_NOTIFICATIONS_CHANNEL);
            this.builder.setContentTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
            if (isGif) {
                this.builder.setTicker(LocaleController.getString("SendingGif", mpEIGo.juqQQs.esbSDO.R.string.SendingGif));
                this.builder.setContentText(LocaleController.getString("SendingGif", mpEIGo.juqQQs.esbSDO.R.string.SendingGif));
            } else {
                this.builder.setTicker(LocaleController.getString("SendingVideo", mpEIGo.juqQQs.esbSDO.R.string.SendingVideo));
                this.builder.setContentText(LocaleController.getString("SendingVideo", mpEIGo.juqQQs.esbSDO.R.string.SendingVideo));
            }
        }
        this.currentProgress = 0;
        this.builder.setProgress(100, 0, 0 == 0);
        startForeground(4, this.builder.build());
        NotificationManagerCompat.from(ApplicationLoader.applicationContext).notify(4, this.builder.build());
        return 2;
    }
}
