package im.uwrkaxlmjj.keepalive;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.IBinder;
import android.os.SystemClock;
import androidx.core.app.NotificationCompat;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.ui.LaunchActivity;
import io.reactivex.Observable;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;
import java.util.concurrent.TimeUnit;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes2.dex */
public class DaemonService extends Service {
    public static final String KEEP_CHANNEL_ID = "imjk.ka.service";
    public static final String KEEP_CHANNEL_NAME = "keep";
    public static final int KEEP_SERVICE_ID = 9510;
    private static final long WAKE_INTERVAL = 900000;
    private Disposable countTimerDis;

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        BroadcastReceiver receiver = new ScreenReceiver();
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction("android.intent.action.SCREEN_OFF");
        intentFilter.addAction("android.intent.action.SCREEN_ON");
        intentFilter.addAction("android.intent.action.USER_PRESENT");
        registerReceiver(receiver, intentFilter);
        startNotification();
        startLoopWake();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        jobReStart();
        return super.onStartCommand(intent, flags, startId);
    }

    @Override // android.app.Service
    public void onDestroy() {
        super.onDestroy();
        try {
            Intent intent = new Intent(getApplicationContext(), (Class<?>) DaemonService.class);
            startService(intent);
        } catch (Throwable e) {
            FileLog.e("DaemonService onDestroy error:" + e.toString());
        }
        stopLoopWake();
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void startNotification() {
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                NotificationChannel notificationChannel = new NotificationChannel(KEEP_CHANNEL_ID, KEEP_CHANNEL_NAME, 4);
                notificationChannel.enableLights(true);
                notificationChannel.setLightColor(-16711936);
                notificationChannel.setShowBadge(true);
                notificationChannel.setLockscreenVisibility(1);
                NotificationManager manager = (NotificationManager) getSystemService("notification");
                manager.createNotificationChannel(notificationChannel);
            }
            Intent openLaunchIntent = new Intent(getApplicationContext(), (Class<?>) LaunchActivity.class);
            openLaunchIntent.addCategory("android.intent.category.LAUNCHER");
            PendingIntent contentIntent = PendingIntent.getActivity(getApplicationContext(), 0, openLaunchIntent, 0);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(this, KEEP_CHANNEL_ID);
            builder.setPriority(2).setSmallIcon(R.id.ic_launcher).setContentTitle(LocaleController.getString(R.string.AppName)).setContentText(LocaleController.getString(R.string.Notifications)).setOngoing(true).setAutoCancel(false).setShowWhen(true).setWhen(System.currentTimeMillis()).setContentIntent(contentIntent);
            Notification notification = builder.build();
            notification.flags |= 64;
            startForeground(KEEP_SERVICE_ID, notification);
        } catch (Throwable e) {
            FileLog.e("DaemonService startNotification error:" + e.toString());
        }
    }

    private void jobReStart() {
        try {
            if (Build.VERSION.SDK_INT >= 21) {
                JobScheduler jobScheduler = (JobScheduler) getSystemService("jobscheduler");
                jobScheduler.cancelAll();
                JobInfo.Builder builder = new JobInfo.Builder(1024, new ComponentName(getPackageName(), ScheduleService.class.getName()));
                builder.setMinimumLatency(WAKE_INTERVAL);
                builder.setRequiredNetworkType(1);
                int schedule = jobScheduler.schedule(builder.build());
                if (schedule <= 0) {
                    FileLog.e("DaemonService schedule error！");
                }
            } else {
                AlarmManager am = (AlarmManager) getSystemService(NotificationCompat.CATEGORY_ALARM);
                Intent alarmIntent = new Intent(getApplication(), (Class<?>) DaemonService.class);
                PendingIntent pendingIntent = PendingIntent.getService(getApplicationContext(), 1024, alarmIntent, 134217728);
                am.cancel(pendingIntent);
                am.setInexactRepeating(2, SystemClock.elapsedRealtime() + WAKE_INTERVAL, WAKE_INTERVAL, pendingIntent);
            }
        } catch (Throwable e) {
            FileLog.e("DaemonService jobReStart error:" + e.toString());
        }
        getPackageManager().setComponentEnabledSetting(new ComponentName(getPackageName(), DaemonService.class.getName()), 1, 1);
    }

    private void startLoopWake() {
        Disposable disposable = this.countTimerDis;
        if (disposable != null && !disposable.isDisposed()) {
            return;
        }
        this.countTimerDis = Observable.interval(DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS, TimeUnit.MILLISECONDS).observeOn(AndroidSchedulers.mainThread()).subscribe(new Consumer() { // from class: im.uwrkaxlmjj.keepalive.-$$Lambda$DaemonService$vByQt2PmjGcZhJc1Yx2394P6Vx0
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                DaemonService.lambda$startLoopWake$0((Long) obj);
            }
        });
    }

    static /* synthetic */ void lambda$startLoopWake$0(Long aLong) throws Exception {
        try {
            FileLog.d("DaemonService timer subscribe");
            ConnectionsManager.getInstance(UserConfig.selectedAccount).resumeNetworkMaybe();
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    private void stopLoopWake() {
        Disposable disposable = this.countTimerDis;
        if (disposable != null && !disposable.isDisposed()) {
            this.countTimerDis.dispose();
        }
    }
}
