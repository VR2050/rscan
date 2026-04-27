package im.uwrkaxlmjj.ui.utils;

import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.util.Base64;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import org.webrtc.utils.RecvStatsReportCommon;

/* JADX INFO: loaded from: classes5.dex */
public class AppUpdater {
    public static final int Gur = 1;
    public static final int Token = 1;
    public static long dismissCheckUpdateTime;
    public static boolean hasChecked;
    private static AppUpdater instance;
    public static long lastUpdateCheckTime;
    private static int mAccount;
    public static TLRPC.TL_help_appUpdate pendingAppUpdate;
    public static int pendingAppUpdateBuildVersion;
    public static long pendingAppUpdateInstallTime;
    private int mRequestToken;

    public interface OnForceUpdateCallback {
        void onForce(TLRPC.TL_help_appUpdate tL_help_appUpdate);

        void onNoUpdate();

        void onNormal(TLRPC.TL_help_appUpdate tL_help_appUpdate);
    }

    private AppUpdater() {
    }

    public static AppUpdater getInstance(int account) {
        synchronized (AppUpdater.class) {
            mAccount = account;
            if (instance == null) {
                instance = new AppUpdater();
            }
        }
        return instance;
    }

    public void checkAppUpdate(final OnForceUpdateCallback callback, final boolean isClick) {
        TLRPC.TL_help_getAppUpdate req = new TLRPC.TL_help_getAppUpdate();
        req.source = RecvStatsReportCommon.sdk_platform;
        this.mRequestToken = ConnectionsManager.getInstance(mAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$AppUpdater$j1YLfLQ6dyMdRGz2EeREVJBPyWw
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkAppUpdate$1$AppUpdater(callback, isClick, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$checkAppUpdate$1$AppUpdater(final OnForceUpdateCallback callback, final boolean isClick, TLObject response, TLRPC.TL_error error) {
        hasChecked = true;
        lastUpdateCheckTime = System.currentTimeMillis();
        if (response instanceof TLRPC.TL_help_appUpdate) {
            final TLRPC.TL_help_appUpdate res = (TLRPC.TL_help_appUpdate) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$AppUpdater$1S1xEd3OZQ--HPQYDZc9T6wJHGo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$AppUpdater(res, callback, isClick);
                }
            });
        } else {
            callback.onNoUpdate();
        }
    }

    public /* synthetic */ void lambda$null$0$AppUpdater(TLRPC.TL_help_appUpdate res, OnForceUpdateCallback callback, boolean isClick) {
        if (res.can_not_skip) {
            pendingAppUpdate = res;
            pendingAppUpdateBuildVersion = BuildVars.BUILD_VERSION;
            try {
                PackageInfo packageInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
                pendingAppUpdateInstallTime = Math.max(packageInfo.lastUpdateTime, packageInfo.firstInstallTime);
            } catch (Exception e) {
                FileLog.e(e);
                pendingAppUpdateInstallTime = 0L;
            }
            lambda$loadUpdateConfig$2$AppUpdater();
            if (callback != null) {
                callback.onForce(res);
                return;
            }
            return;
        }
        if ((isClick || Math.abs(System.currentTimeMillis() - dismissCheckUpdateTime) >= 43200000) && callback != null) {
            callback.onNormal(res);
        }
    }

    public void cancel() {
        if (this.mRequestToken != 0) {
            ConnectionsManager.getInstance(mAccount).cancelRequest(this.mRequestToken, true);
        }
    }

    /* JADX INFO: renamed from: saveUpdateConfig, reason: merged with bridge method [inline-methods] */
    public void lambda$loadUpdateConfig$2$AppUpdater() {
        SharedPreferences.Editor editor = getPreferences().edit();
        TLRPC.TL_help_appUpdate tL_help_appUpdate = pendingAppUpdate;
        if (tL_help_appUpdate != null) {
            try {
                SerializedData data = new SerializedData(tL_help_appUpdate.getObjectSize());
                pendingAppUpdate.serializeToStream(data);
                String str = Base64.encodeToString(data.toByteArray(), 0);
                editor.putString("appUpdate", str);
                editor.putInt("appUpdateBuild", pendingAppUpdateBuildVersion);
                editor.putLong("appUpdateTime", pendingAppUpdateInstallTime);
                data.cleanup();
                return;
            } catch (Exception e) {
                return;
            }
        }
        editor.remove("appUpdate");
    }

    public void loadUpdateConfig() {
        SharedPreferences preferences = getPreferences();
        if (mAccount == 0) {
            try {
                String update = preferences.getString("appUpdate", null);
                if (update != null) {
                    pendingAppUpdateBuildVersion = preferences.getInt("appUpdateBuild", BuildVars.BUILD_VERSION);
                    pendingAppUpdateInstallTime = preferences.getLong("appUpdateTime", System.currentTimeMillis());
                    byte[] arr = Base64.decode(update, 0);
                    if (arr != null) {
                        SerializedData data = new SerializedData(arr);
                        pendingAppUpdate = (TLRPC.TL_help_appUpdate) TLRPC.help_AppUpdate.TLdeserialize(data, data.readInt32(false), false);
                        data.cleanup();
                    }
                }
                if (pendingAppUpdate != null) {
                    long updateTime = 0;
                    try {
                        PackageInfo packageInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
                        updateTime = Math.max(packageInfo.lastUpdateTime, packageInfo.firstInstallTime);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                    if (pendingAppUpdateBuildVersion != BuildVars.BUILD_VERSION || pendingAppUpdateInstallTime < updateTime) {
                        pendingAppUpdate = null;
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$AppUpdater$GLLnOVLmx9EBlIJ-EU1inseD51s
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$loadUpdateConfig$2$AppUpdater();
                            }
                        });
                    }
                }
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
    }

    private SharedPreferences getPreferences() {
        return ApplicationLoader.applicationContext.getSharedPreferences("update_config", 0);
    }
}
