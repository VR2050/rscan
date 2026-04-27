package com.google.android.exoplayer2.offline;

import android.app.Notification;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import com.google.android.exoplayer2.offline.DownloadManager;
import com.google.android.exoplayer2.scheduler.Requirements;
import com.google.android.exoplayer2.scheduler.Scheduler;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Log;
import com.google.android.exoplayer2.util.NotificationUtil;
import com.google.android.exoplayer2.util.Util;
import java.util.HashMap;

/* JADX INFO: loaded from: classes2.dex */
public abstract class DownloadService extends Service {
    public static final String ACTION_ADD = "com.google.android.exoplayer.downloadService.action.ADD";
    public static final String ACTION_INIT = "com.google.android.exoplayer.downloadService.action.INIT";
    private static final String ACTION_RESTART = "com.google.android.exoplayer.downloadService.action.RESTART";
    private static final boolean DEBUG = false;
    public static final long DEFAULT_FOREGROUND_NOTIFICATION_UPDATE_INTERVAL = 1000;
    public static final int FOREGROUND_NOTIFICATION_ID_NONE = 0;
    public static final String KEY_DOWNLOAD_ACTION = "download_action";
    public static final String KEY_FOREGROUND = "foreground";
    private static final String TAG = "DownloadService";
    private static final HashMap<Class<? extends DownloadService>, DownloadManagerHelper> downloadManagerListeners = new HashMap<>();
    private final String channelId;
    private final int channelName;
    private DownloadManager downloadManager;
    private final ForegroundNotificationUpdater foregroundNotificationUpdater;
    private int lastStartId;
    private boolean startedInForeground;
    private boolean taskRemoved;

    protected abstract DownloadManager getDownloadManager();

    protected abstract Scheduler getScheduler();

    protected DownloadService(int foregroundNotificationId) {
        this(foregroundNotificationId, 1000L);
    }

    protected DownloadService(int foregroundNotificationId, long foregroundNotificationUpdateInterval) {
        this(foregroundNotificationId, foregroundNotificationUpdateInterval, null, 0);
    }

    protected DownloadService(int foregroundNotificationId, long foregroundNotificationUpdateInterval, String channelId, int channelName) {
        this.foregroundNotificationUpdater = foregroundNotificationId == 0 ? null : new ForegroundNotificationUpdater(foregroundNotificationId, foregroundNotificationUpdateInterval);
        this.channelId = channelId;
        this.channelName = channelName;
    }

    public static Intent buildAddActionIntent(Context context, Class<? extends DownloadService> clazz, DownloadAction downloadAction, boolean foreground) {
        return getIntent(context, clazz, ACTION_ADD).putExtra(KEY_DOWNLOAD_ACTION, downloadAction.toByteArray()).putExtra(KEY_FOREGROUND, foreground);
    }

    public static void startWithAction(Context context, Class<? extends DownloadService> clazz, DownloadAction downloadAction, boolean foreground) {
        Intent intent = buildAddActionIntent(context, clazz, downloadAction, foreground);
        if (foreground) {
            Util.startForegroundService(context, intent);
        } else {
            context.startService(intent);
        }
    }

    public static void start(Context context, Class<? extends DownloadService> clazz) {
        context.startService(getIntent(context, clazz, ACTION_INIT));
    }

    public static void startForeground(Context context, Class<? extends DownloadService> clazz) {
        Intent intent = getIntent(context, clazz, ACTION_INIT).putExtra(KEY_FOREGROUND, true);
        Util.startForegroundService(context, intent);
    }

    @Override // android.app.Service
    public void onCreate() {
        logd("onCreate");
        String str = this.channelId;
        if (str != null) {
            NotificationUtil.createNotificationChannel(this, str, this.channelName, 2);
        }
        Class<?> cls = getClass();
        DownloadManagerHelper downloadManagerHelper = downloadManagerListeners.get(cls);
        if (downloadManagerHelper == null) {
            downloadManagerHelper = new DownloadManagerHelper(getApplicationContext(), getDownloadManager(), getScheduler(), cls);
            downloadManagerListeners.put((Class<? extends DownloadService>) cls, downloadManagerHelper);
        }
        this.downloadManager = downloadManagerHelper.downloadManager;
        downloadManagerHelper.attachService(this);
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0077  */
    @Override // android.app.Service
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int onStartCommand(android.content.Intent r9, int r10, int r11) {
        /*
            r8 = this;
            r8.lastStartId = r11
            r0 = 0
            r8.taskRemoved = r0
            r1 = 0
            java.lang.String r2 = "com.google.android.exoplayer.downloadService.action.RESTART"
            r3 = 1
            if (r9 == 0) goto L26
            java.lang.String r1 = r9.getAction()
            boolean r4 = r8.startedInForeground
            java.lang.String r5 = "foreground"
            boolean r5 = r9.getBooleanExtra(r5, r0)
            if (r5 != 0) goto L22
            boolean r5 = r2.equals(r1)
            if (r5 == 0) goto L20
            goto L22
        L20:
            r5 = 0
            goto L23
        L22:
            r5 = 1
        L23:
            r4 = r4 | r5
            r8.startedInForeground = r4
        L26:
            if (r1 != 0) goto L2a
            java.lang.String r1 = "com.google.android.exoplayer.downloadService.action.INIT"
        L2a:
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            java.lang.String r5 = "onStartCommand action: "
            r4.append(r5)
            r4.append(r1)
            java.lang.String r5 = " startId: "
            r4.append(r5)
            r4.append(r11)
            java.lang.String r4 = r4.toString()
            r8.logd(r4)
            r4 = -1
            int r5 = r1.hashCode()
            r6 = -871181424(0xffffffffcc12d390, float:-3.8489664E7)
            r7 = 2
            if (r5 == r6) goto L6f
            r2 = -382886238(0xffffffffe92d9ea2, float:-1.311833E25)
            if (r5 == r2) goto L65
            r2 = 1015676687(0x3c89ff0f, float:0.016845254)
            if (r5 == r2) goto L5c
        L5b:
            goto L77
        L5c:
            java.lang.String r2 = "com.google.android.exoplayer.downloadService.action.INIT"
            boolean r2 = r1.equals(r2)
            if (r2 == 0) goto L5b
            goto L78
        L65:
            java.lang.String r0 = "com.google.android.exoplayer.downloadService.action.ADD"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L5b
            r0 = 2
            goto L78
        L6f:
            boolean r0 = r1.equals(r2)
            if (r0 == 0) goto L5b
            r0 = 1
            goto L78
        L77:
            r0 = -1
        L78:
            if (r0 == 0) goto Lb4
            if (r0 == r3) goto Lb4
            java.lang.String r2 = "DownloadService"
            if (r0 == r7) goto L95
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r4 = "Ignoring unrecognized action: "
            r0.append(r4)
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            com.google.android.exoplayer2.util.Log.e(r2, r0)
            goto Lb5
        L95:
            java.lang.String r0 = "download_action"
            byte[] r0 = r9.getByteArrayExtra(r0)
            if (r0 != 0) goto La3
            java.lang.String r4 = "Ignoring ADD action with no action data"
            com.google.android.exoplayer2.util.Log.e(r2, r4)
            goto Lb5
        La3:
            com.google.android.exoplayer2.offline.DownloadManager r4 = r8.downloadManager     // Catch: java.io.IOException -> Lad
            com.google.android.exoplayer2.offline.DownloadAction r5 = com.google.android.exoplayer2.offline.DownloadAction.fromByteArray(r0)     // Catch: java.io.IOException -> Lad
            r4.handleAction(r5)     // Catch: java.io.IOException -> Lad
            goto Lb5
        Lad:
            r4 = move-exception
            java.lang.String r5 = "Failed to handle ADD action"
            com.google.android.exoplayer2.util.Log.e(r2, r5, r4)
            goto Lb5
        Lb4:
        Lb5:
            com.google.android.exoplayer2.offline.DownloadManager r0 = r8.downloadManager
            boolean r0 = r0.isIdle()
            if (r0 == 0) goto Lc0
            r8.stop()
        Lc0:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.offline.DownloadService.onStartCommand(android.content.Intent, int, int):int");
    }

    @Override // android.app.Service
    public void onTaskRemoved(Intent rootIntent) {
        logd("onTaskRemoved rootIntent: " + rootIntent);
        this.taskRemoved = true;
    }

    @Override // android.app.Service
    public void onDestroy() {
        logd("onDestroy");
        DownloadManagerHelper downloadManagerHelper = downloadManagerListeners.get(getClass());
        boolean unschedule = this.downloadManager.getDownloadCount() <= 0;
        downloadManagerHelper.detachService(this, unschedule);
        ForegroundNotificationUpdater foregroundNotificationUpdater = this.foregroundNotificationUpdater;
        if (foregroundNotificationUpdater != null) {
            foregroundNotificationUpdater.stopPeriodicUpdates();
        }
    }

    @Override // android.app.Service
    public final IBinder onBind(Intent intent) {
        throw new UnsupportedOperationException();
    }

    protected Notification getForegroundNotification(DownloadState[] downloadStates) {
        throw new IllegalStateException(getClass().getName() + " is started in the foreground but getForegroundNotification() is not implemented.");
    }

    protected void onDownloadStateChanged(DownloadState downloadState) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyDownloadStateChange(DownloadState downloadState) {
        onDownloadStateChanged(downloadState);
        if (this.foregroundNotificationUpdater != null) {
            if (downloadState.state == 2 || downloadState.state == 5 || downloadState.state == 7) {
                this.foregroundNotificationUpdater.startPeriodicUpdates();
            } else {
                this.foregroundNotificationUpdater.update();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void stop() {
        ForegroundNotificationUpdater foregroundNotificationUpdater = this.foregroundNotificationUpdater;
        if (foregroundNotificationUpdater != null) {
            foregroundNotificationUpdater.stopPeriodicUpdates();
            if (this.startedInForeground && Util.SDK_INT >= 26) {
                this.foregroundNotificationUpdater.showNotificationIfNotAlready();
            }
        }
        if (Util.SDK_INT < 28 && this.taskRemoved) {
            stopSelf();
            logd("stopSelf()");
            return;
        }
        boolean stopSelfResult = stopSelfResult(this.lastStartId);
        logd("stopSelf(" + this.lastStartId + ") result: " + stopSelfResult);
    }

    private void logd(String message) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Intent getIntent(Context context, Class<? extends DownloadService> clazz, String action) {
        return new Intent(context, clazz).setAction(action);
    }

    private final class ForegroundNotificationUpdater implements Runnable {
        private final Handler handler = new Handler(Looper.getMainLooper());
        private boolean notificationDisplayed;
        private final int notificationId;
        private boolean periodicUpdatesStarted;
        private final long updateInterval;

        public ForegroundNotificationUpdater(int notificationId, long updateInterval) {
            this.notificationId = notificationId;
            this.updateInterval = updateInterval;
        }

        public void startPeriodicUpdates() {
            this.periodicUpdatesStarted = true;
            update();
        }

        public void stopPeriodicUpdates() {
            this.periodicUpdatesStarted = false;
            this.handler.removeCallbacks(this);
        }

        public void update() {
            DownloadState[] downloadStates = DownloadService.this.downloadManager.getAllDownloadStates();
            DownloadService downloadService = DownloadService.this;
            downloadService.startForeground(this.notificationId, downloadService.getForegroundNotification(downloadStates));
            this.notificationDisplayed = true;
            if (this.periodicUpdatesStarted) {
                this.handler.removeCallbacks(this);
                this.handler.postDelayed(this, this.updateInterval);
            }
        }

        public void showNotificationIfNotAlready() {
            if (!this.notificationDisplayed) {
                update();
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            update();
        }
    }

    private static final class DownloadManagerHelper implements DownloadManager.Listener {
        private final Context context;
        private final DownloadManager downloadManager;
        private DownloadService downloadService;
        private final Scheduler scheduler;
        private final Class<? extends DownloadService> serviceClass;

        private DownloadManagerHelper(Context context, DownloadManager downloadManager, Scheduler scheduler, Class<? extends DownloadService> serviceClass) {
            this.context = context;
            this.downloadManager = downloadManager;
            this.scheduler = scheduler;
            this.serviceClass = serviceClass;
            downloadManager.addListener(this);
            if (scheduler != null) {
                Requirements requirements = downloadManager.getRequirements();
                setSchedulerEnabled(!requirements.checkRequirements(context), requirements);
            }
        }

        public void attachService(DownloadService downloadService) {
            Assertions.checkState(this.downloadService == null);
            this.downloadService = downloadService;
        }

        public void detachService(DownloadService downloadService, boolean unschedule) {
            Assertions.checkState(this.downloadService == downloadService);
            this.downloadService = null;
            if (unschedule) {
                this.scheduler.cancel();
            }
        }

        @Override // com.google.android.exoplayer2.offline.DownloadManager.Listener
        public void onInitialized(DownloadManager downloadManager) {
        }

        @Override // com.google.android.exoplayer2.offline.DownloadManager.Listener
        public void onDownloadStateChanged(DownloadManager downloadManager, DownloadState downloadState) {
            DownloadService downloadService = this.downloadService;
            if (downloadService != null) {
                downloadService.notifyDownloadStateChange(downloadState);
            }
        }

        @Override // com.google.android.exoplayer2.offline.DownloadManager.Listener
        public final void onIdle(DownloadManager downloadManager) {
            DownloadService downloadService = this.downloadService;
            if (downloadService != null) {
                downloadService.stop();
            }
        }

        @Override // com.google.android.exoplayer2.offline.DownloadManager.Listener
        public void onRequirementsStateChanged(DownloadManager downloadManager, Requirements requirements, int notMetRequirements) {
            boolean requirementsMet = notMetRequirements == 0;
            if (this.downloadService == null && requirementsMet) {
                try {
                    Intent intent = DownloadService.getIntent(this.context, this.serviceClass, DownloadService.ACTION_INIT);
                    this.context.startService(intent);
                } catch (IllegalStateException e) {
                    return;
                }
            }
            if (this.scheduler != null) {
                setSchedulerEnabled(requirementsMet ? false : true, requirements);
            }
        }

        private void setSchedulerEnabled(boolean enabled, Requirements requirements) {
            if (!enabled) {
                this.scheduler.cancel();
                return;
            }
            String servicePackage = this.context.getPackageName();
            boolean success = this.scheduler.schedule(requirements, servicePackage, DownloadService.ACTION_RESTART);
            if (!success) {
                Log.e(DownloadService.TAG, "Scheduling downloads failed.");
            }
        }
    }
}
