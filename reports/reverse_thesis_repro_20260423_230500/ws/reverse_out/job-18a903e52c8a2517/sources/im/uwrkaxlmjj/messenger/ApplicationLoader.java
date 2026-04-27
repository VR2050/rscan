package im.uwrkaxlmjj.messenger;

import android.app.AlarmManager;
import android.app.Application;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Handler;
import android.os.PowerManager;
import android.os.Process;
import android.text.TextUtils;
import androidx.core.app.NotificationCompat;
import com.bjz.comm.net.utils.AppPreferenceUtil;
import com.google.android.exoplayer2.util.Log;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;
import im.uwrkaxlmjj.network.NetWorkManager;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.ForegroundDetector;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.fragments.LogUpLoad;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.DatabaseInstance;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.utils.ThirdPartSdkInitUtil;
import java.io.File;
import java.lang.Thread;

/* JADX INFO: loaded from: classes2.dex */
public class ApplicationLoader extends Application implements Constants, Thread.UncaughtExceptionHandler {
    public static volatile Context applicationContext;
    public static volatile Handler applicationHandler;
    private static ConnectivityManager connectivityManager;
    public static volatile NetworkInfo currentNetworkInfo;
    public static boolean hasPlayServices;
    public static volatile long mainInterfacePausedStageQueueTime;
    public static String thirdAppName;
    public static volatile boolean unableGetCurrentNetwork;
    private boolean mBlnSendUPushToken = false;
    private static volatile boolean applicationInited = false;
    public static volatile boolean isScreenOn = false;
    public static volatile boolean mainInterfacePaused = true;
    public static volatile boolean externalInterfacePaused = true;
    public static volatile boolean mainInterfacePausedStageQueue = true;
    public static String strDeviceKey = "";
    public static byte mbytMessageReged = 0;
    public static volatile byte mbytAVideoCallBusy = 0;
    public static volatile byte mbytLiving = 0;
    public static boolean blnShowAuth = false;

    public static File getFilesDirFixed() {
        for (int a = 0; a < 10; a++) {
            File path = applicationContext.getFilesDir();
            if (path != null) {
                return path;
            }
        }
        try {
            ApplicationInfo info = applicationContext.getApplicationInfo();
            File path2 = new File(info.dataDir, "files");
            path2.mkdirs();
            return path2;
        } catch (Exception e) {
            FileLog.e(e);
            return new File("/data/data/im.uwrkaxlmjj.messenger/files");
        }
    }

    public static void postInitApplication() {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("SDKINIT  ===> ApplicationLoader postInitApplication app init ===> start , iid = " + applicationInited + " , preparedId = true");
        }
        if (applicationInited) {
            return;
        }
        applicationInited = true;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$VdlDIVlbPS74P_Svh48hPou8f0M
            @Override // java.lang.Runnable
            public final void run() {
                ApplicationLoader.startPushService();
            }
        });
        try {
            LocaleController.getInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            connectivityManager = (ConnectivityManager) applicationContext.getSystemService("connectivity");
            BroadcastReceiver networkStateReceiver = new BroadcastReceiver() { // from class: im.uwrkaxlmjj.messenger.ApplicationLoader.1
                @Override // android.content.BroadcastReceiver
                public void onReceive(Context context, Intent intent) {
                    try {
                        ApplicationLoader.currentNetworkInfo = ApplicationLoader.connectivityManager.getActiveNetworkInfo();
                    } catch (Throwable th) {
                    }
                    boolean isSlow = ApplicationLoader.isConnectionSlow();
                    for (int a = 0; a < 3; a++) {
                        ConnectionsManager.getInstance(a).checkConnection();
                        FileLoader.getInstance(a).onNetworkChanged(isSlow);
                    }
                }
            };
            applicationContext.registerReceiver(networkStateReceiver, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        try {
            IntentFilter filter = new IntentFilter("android.intent.action.SCREEN_ON");
            filter.addAction("android.intent.action.SCREEN_OFF");
            BroadcastReceiver mReceiver = new ScreenReceiver();
            applicationContext.registerReceiver(mReceiver, filter);
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        try {
            PowerManager pm = (PowerManager) applicationContext.getSystemService("power");
            isScreenOn = pm.isScreenOn();
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("ApplicationLoader ---> postInitApplication screen state = " + isScreenOn);
            }
        } catch (Exception e4) {
            FileLog.e(e4);
        }
        SharedConfig.loadConfig();
        for (int a = 0; a < 3; a++) {
            UserConfig.getInstance(a).loadConfig();
            MessagesController.getInstance(a);
            if (a == 0) {
                SharedConfig.pushStringStatus = "__FIREBASE_GENERATING_SINCE_" + ConnectionsManager.getInstance(a).getCurrentTime() + "__";
            } else {
                ConnectionsManager.getInstance(a);
            }
            TLRPC.User user = UserConfig.getInstance(a).getCurrentUser();
            if (user != null) {
                MessagesController.getInstance(a).putUser(user, true);
                SendMessagesHelper.getInstance(a).checkUnsentMessages();
            }
        }
        ApplicationLoader app = (ApplicationLoader) applicationContext;
        app.initPlayServices();
        MediaController.getInstance();
        for (int a2 = 0; a2 < 3; a2++) {
            ContactsController.getInstance(a2).checkAppAccount();
            DownloadController.getInstance(a2);
        }
        NetWorkManager.getInstance().initNetWork();
        WearDataLayerListenerService.updateWatchConnectionState();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("SDKINIT  ===> ApplicationLoader postInitApplication app init end");
        }
        ThirdPartSdkInitUtil.initOtherSdk(applicationContext);
    }

    @Override // android.app.Application
    public void onCreate() {
        try {
            applicationContext = getApplicationContext();
        } catch (Throwable th) {
        }
        super.onCreate();
        if (applicationContext == null) {
            applicationContext = getApplicationContext();
        }
        Thread.setDefaultUncaughtExceptionHandler(this);
        int pid = Process.myPid();
        Log.d("bond", "进程ID= " + pid);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("SDKINIT  ===> ApplicationLoader onCreate init start");
        }
        NativeLoader.initNativeLibs(applicationContext);
        ConnectionsManager.native_setJava(false);
        new ForegroundDetector(this);
        applicationHandler = new Handler(applicationContext.getMainLooper());
        AppPreferenceUtil.initSharedPreferences(applicationContext);
        DatabaseInstance.getInstance(applicationContext);
        ToastUtils.init(applicationContext);
        FcToastUtils.init(applicationContext);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("SDKINIT  ===> ApplicationLoader onCreate init end");
        }
    }

    private void sendUPushTokenToServer() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ApplicationLoader$UQ0cInfLI1Ji0Y-tnohJ267xN5Q
            @Override // java.lang.Runnable
            public final void run() {
                GcmPushListenerService.sendUPushRegistrationToServer(ApplicationLoader.strDeviceKey);
            }
        });
    }

    public static void startPushService() {
        Log.d(Constants.SDK_INIT_TAG, applicationContext.toString() + " startPushService ===> start");
        SharedPreferences preferences = MessagesController.getGlobalNotificationsSettings();
        if (preferences.getBoolean("pushService", true)) {
            try {
                applicationContext.startService(new Intent(applicationContext, (Class<?>) NotificationsService.class));
            } catch (Throwable th) {
            }
        } else {
            stopPushService();
        }
        Log.d(Constants.SDK_INIT_TAG, applicationContext.toString() + " startPushService ===> end");
    }

    public static void stopPushService() {
        applicationContext.stopService(new Intent(applicationContext, (Class<?>) NotificationsService.class));
        PendingIntent pintent = PendingIntent.getService(applicationContext, 0, new Intent(applicationContext, (Class<?>) NotificationsService.class), 0);
        AlarmManager alarm = (AlarmManager) applicationContext.getSystemService(NotificationCompat.CATEGORY_ALARM);
        alarm.cancel(pintent);
    }

    @Override // android.app.Application, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        try {
            LocaleController.getInstance().onDeviceConfigurationChange(newConfig);
            AndroidUtilities.checkDisplaySize(applicationContext, newConfig);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initPlayServices() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ApplicationLoader$PzxtkUkIpS9Xyqeyv5zjHUikhcs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$initPlayServices$4$ApplicationLoader();
            }
        }, 1000L);
    }

    public /* synthetic */ void lambda$initPlayServices$4$ApplicationLoader() {
        boolean zCheckPlayServices = checkPlayServices();
        hasPlayServices = zCheckPlayServices;
        if (zCheckPlayServices) {
            String currentPushString = SharedConfig.pushString;
            if (!TextUtils.isEmpty(currentPushString)) {
                if (BuildVars.DEBUG_PRIVATE_VERSION && BuildVars.LOGS_ENABLED) {
                    FileLog.d("ApplicationLoader ---> initPlayServices GCM regId = " + currentPushString);
                }
            } else if (BuildVars.LOGS_ENABLED) {
                FileLog.d("ApplicationLoFader ---> initPlayServices GCM Registration not found.");
            }
            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ApplicationLoader$OimudhXx1yhrQSk9qicK4phmK8o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$ApplicationLoader();
                }
            });
            return;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("ApplicationLoader ---> No valid Google Play Services APK found.");
        }
        SharedConfig.pushStringStatus = "__NO_GOOGLE_PLAY_SERVICES__";
        FileLog.d("ApplicationLoader ---> umeng strDeviceKey = " + strDeviceKey);
        if (!TextUtils.isEmpty(strDeviceKey)) {
            GcmPushListenerService.sendUPushRegistrationToServer(strDeviceKey);
        } else {
            this.mBlnSendUPushToken = true;
        }
    }

    public /* synthetic */ void lambda$null$3$ApplicationLoader() {
        try {
            FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(new OnSuccessListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ApplicationLoader$n2Z7SvTFcXnSh3Hf7WbuXCSYxgk
                @Override // com.google.android.gms.tasks.OnSuccessListener
                public final void onSuccess(Object obj) {
                    ApplicationLoader.lambda$null$1((InstanceIdResult) obj);
                }
            }).addOnFailureListener(new OnFailureListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ApplicationLoader$zODQWjHwMRBs2ZkKOiIYmyhMenI
                @Override // com.google.android.gms.tasks.OnFailureListener
                public final void onFailure(Exception exc) {
                    this.f$0.lambda$null$2$ApplicationLoader(exc);
                }
            });
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ void lambda$null$1(InstanceIdResult instanceIdResult) {
        String token = instanceIdResult.getToken();
        if (!TextUtils.isEmpty(token)) {
            GcmPushListenerService.sendRegistrationToServer(token);
        }
    }

    public /* synthetic */ void lambda$null$2$ApplicationLoader(Exception e) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("ApplicationLoader ---> initPlayServices Failed to get regid");
        }
        SharedConfig.pushStringStatus = "__FIREBASE_FAILED__";
        if (!TextUtils.isEmpty(strDeviceKey)) {
            GcmPushListenerService.sendUPushRegistrationToServer(strDeviceKey);
        } else {
            this.mBlnSendUPushToken = true;
        }
    }

    private boolean checkPlayServices() {
        try {
            int resultCode = GooglePlayServicesUtil.isGooglePlayServicesAvailable(this);
            return resultCode == 0;
        } catch (Exception e) {
            FileLog.e(e);
            return true;
        }
    }

    public static boolean isRoaming() {
        try {
            ConnectivityManager connectivityManager2 = (ConnectivityManager) applicationContext.getSystemService("connectivity");
            NetworkInfo netInfo = connectivityManager2.getActiveNetworkInfo();
            if (netInfo != null) {
                return netInfo.isRoaming();
            }
            return false;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    public static boolean isConnectedOrConnectingToWiFi() {
        try {
            ConnectivityManager connectivityManager2 = (ConnectivityManager) applicationContext.getSystemService("connectivity");
            NetworkInfo netInfo = connectivityManager2.getNetworkInfo(1);
            NetworkInfo.State state = netInfo.getState();
            if (netInfo != null) {
                if (state != NetworkInfo.State.CONNECTED && state != NetworkInfo.State.CONNECTING) {
                    if (state != NetworkInfo.State.SUSPENDED) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    public static boolean isConnectedToWiFi() {
        try {
            ConnectivityManager connectivityManager2 = (ConnectivityManager) applicationContext.getSystemService("connectivity");
            NetworkInfo netInfo = connectivityManager2.getNetworkInfo(1);
            if (netInfo == null) {
                return false;
            }
            if (netInfo.getState() == NetworkInfo.State.CONNECTED) {
                return true;
            }
            return false;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    public static int getCurrentNetworkType() {
        if (isConnectedOrConnectingToWiFi()) {
            return 1;
        }
        if (isRoaming()) {
            return 2;
        }
        return 0;
    }

    public static boolean isConnectionSlow() {
        try {
            ConnectivityManager connectivityManager2 = (ConnectivityManager) applicationContext.getSystemService("connectivity");
            NetworkInfo netInfo = connectivityManager2.getActiveNetworkInfo();
            if (netInfo.getType() == 0) {
                int subtype = netInfo.getSubtype();
                return subtype == 1 || subtype == 2 || subtype == 4 || subtype == 7 || subtype == 11;
            }
            return false;
        } catch (Throwable th) {
            return false;
        }
    }

    public static boolean isNetworkOnline() {
        try {
            ConnectivityManager connectivityManager2 = (ConnectivityManager) applicationContext.getSystemService("connectivity");
            NetworkInfo netInfo = connectivityManager2.getActiveNetworkInfo();
            if (netInfo != null && (netInfo.isConnectedOrConnecting() || netInfo.isAvailable())) {
                return true;
            }
            NetworkInfo netInfo2 = connectivityManager2.getNetworkInfo(0);
            if (netInfo2 != null && netInfo2.isConnectedOrConnecting()) {
                return true;
            }
            NetworkInfo netInfo3 = connectivityManager2.getNetworkInfo(1);
            if (netInfo3 != null) {
                if (netInfo3.isConnectedOrConnecting()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            FileLog.e(e);
            return true;
        }
    }

    @Override // android.app.Application
    public void onTerminate() {
        super.onTerminate();
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public void uncaughtException(Thread thread, Throwable throwable) {
        FileLog.e(throwable);
        LogUpLoad.uploadLogFile(AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().clientUserId);
    }
}
