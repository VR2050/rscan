package im.uwrkaxlmjj.messenger;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import im.uwrkaxlmjj.messenger.LocationController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.LaunchActivity;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes2.dex */
public class LocationSharingService extends Service implements NotificationCenter.NotificationCenterDelegate {
    private NotificationCompat.Builder builder;
    private Handler handler;
    private Runnable runnable;

    public LocationSharingService() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.liveLocationsChanged);
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        this.handler = new Handler();
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationSharingService$O2Z_-vlnSPXUSqXAne56Tfw7dm0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onCreate$1$LocationSharingService();
            }
        };
        this.runnable = runnable;
        this.handler.postDelayed(runnable, 1000L);
    }

    public /* synthetic */ void lambda$onCreate$1$LocationSharingService() {
        this.handler.postDelayed(this.runnable, 1000L);
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationSharingService$9rP-7nZ8WpejikbqqfPErWRhDjs
            @Override // java.lang.Runnable
            public final void run() {
                LocationSharingService.lambda$null$0();
            }
        });
    }

    static /* synthetic */ void lambda$null$0() {
        for (int a = 0; a < 3; a++) {
            LocationController.getInstance(a).update();
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent arg2) {
        return null;
    }

    @Override // android.app.Service
    public void onDestroy() {
        super.onDestroy();
        Handler handler = this.handler;
        if (handler != null) {
            handler.removeCallbacks(this.runnable);
        }
        stopForeground(true);
        NotificationManagerCompat.from(ApplicationLoader.applicationContext).cancel(6);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.liveLocationsChanged);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        Handler handler;
        if (id == NotificationCenter.liveLocationsChanged && (handler = this.handler) != null) {
            handler.post(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationSharingService$s-gEScKJjhnzPhJB4Ufm7eUzUEw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$didReceivedNotification$2$LocationSharingService();
                }
            });
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$2$LocationSharingService() {
        ArrayList<LocationController.SharingLocationInfo> infos = getInfos();
        if (infos.isEmpty()) {
            stopSelf();
        } else {
            updateNotification(true);
        }
    }

    private ArrayList<LocationController.SharingLocationInfo> getInfos() {
        ArrayList<LocationController.SharingLocationInfo> infos = new ArrayList<>();
        for (int a = 0; a < 3; a++) {
            ArrayList<LocationController.SharingLocationInfo> arrayList = LocationController.getInstance(a).sharingLocationsUI;
            if (!arrayList.isEmpty()) {
                infos.addAll(arrayList);
            }
        }
        return infos;
    }

    private void updateNotification(boolean post) {
        String param;
        if (this.builder == null) {
            return;
        }
        ArrayList<LocationController.SharingLocationInfo> infos = getInfos();
        if (infos.size() == 1) {
            LocationController.SharingLocationInfo info = infos.get(0);
            int lower_id = (int) info.messageObject.getDialogId();
            int currentAccount = info.messageObject.currentAccount;
            if (lower_id > 0) {
                TLRPC.User user = MessagesController.getInstance(currentAccount).getUser(Integer.valueOf(lower_id));
                param = UserObject.getFirstName(user);
            } else {
                TLRPC.Chat chat = MessagesController.getInstance(currentAccount).getChat(Integer.valueOf(-lower_id));
                if (chat != null) {
                    param = chat.title;
                } else {
                    param = "";
                }
            }
        } else {
            param = LocaleController.formatPluralString("Chats", infos.size());
        }
        String str = String.format(LocaleController.getString("AttachLiveLocationIsSharing", mpEIGo.juqQQs.esbSDO.R.string.AttachLiveLocationIsSharing), LocaleController.getString("AttachLiveLocation", mpEIGo.juqQQs.esbSDO.R.string.AttachLiveLocation), param);
        this.builder.setTicker(str);
        this.builder.setContentText(str);
        if (post) {
            NotificationManagerCompat.from(ApplicationLoader.applicationContext).notify(6, this.builder.build());
        }
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (getInfos().isEmpty()) {
            stopSelf();
        }
        if (this.builder == null) {
            Intent intent2 = new Intent(ApplicationLoader.applicationContext, (Class<?>) LaunchActivity.class);
            intent2.setAction("org.tmessages.openlocations");
            intent2.addCategory("android.intent.category.LAUNCHER");
            PendingIntent contentIntent = PendingIntent.getActivity(ApplicationLoader.applicationContext, 0, intent2, 0);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(ApplicationLoader.applicationContext);
            this.builder = builder;
            builder.setWhen(System.currentTimeMillis());
            this.builder.setSmallIcon(mpEIGo.juqQQs.esbSDO.R.drawable.live_loc);
            this.builder.setContentIntent(contentIntent);
            NotificationsController.checkOtherNotificationsChannel();
            this.builder.setChannelId(NotificationsController.OTHER_NOTIFICATIONS_CHANNEL);
            this.builder.setContentTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
            Intent stopIntent = new Intent(ApplicationLoader.applicationContext, (Class<?>) StopLiveLocationReceiver.class);
            this.builder.addAction(0, LocaleController.getString("StopLiveLocation", mpEIGo.juqQQs.esbSDO.R.string.StopLiveLocation), PendingIntent.getBroadcast(ApplicationLoader.applicationContext, 2, stopIntent, 134217728));
        }
        updateNotification(false);
        startForeground(6, this.builder.build());
        return 2;
    }
}
