package com.fm.openinstall;

import android.app.Activity;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import com.fm.openinstall.listener.AppInstallListener;
import com.fm.openinstall.listener.AppInstallRetryAdapter;
import com.fm.openinstall.listener.AppWakeUpListener;
import com.fm.openinstall.listener.ResultCallback;
import com.fm.openinstall.model.Error;
import io.openinstall.sdk.a;
import io.openinstall.sdk.as;
import io.openinstall.sdk.cy;
import io.openinstall.sdk.ea;
import io.openinstall.sdk.ec;
import java.io.File;
import java.lang.ref.WeakReference;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public final class OpenInstall {
    private static volatile boolean a = false;
    private static volatile boolean b = false;

    private OpenInstall() {
    }

    private static boolean a() {
        if (b) {
            return true;
        }
        if (ec.a) {
            ec.c("请先调用 init(Context) 初始化", new Object[0]);
        }
        return false;
    }

    public static void clipBoardEnabled(boolean z) {
        as.a().a(Boolean.valueOf(z));
    }

    public static void getInstall(AppInstallListener appInstallListener) {
        getInstall(appInstallListener, 10);
    }

    public static void getInstall(AppInstallListener appInstallListener, int i) {
        if (!a()) {
            appInstallListener.onInstallFinish(null, Error.fromInner(cy.a.NOT_INIT));
            return;
        }
        if (ec.a && i < 5) {
            ec.b("getInstall设置超时时间过小，易造成数据获取失败，请增大超时时间或调整调用时机", new Object[0]);
        }
        a.a().a(false, i, appInstallListener);
    }

    public static void getInstallCanRetry(AppInstallRetryAdapter appInstallRetryAdapter, int i) {
        if (a()) {
            a.a().a(true, i, (AppInstallListener) appInstallRetryAdapter);
        } else {
            cy.a.NOT_INIT.a();
            appInstallRetryAdapter.onInstallFinish(null, Error.fromInner(cy.a.NOT_INIT));
        }
    }

    public static String getOpid() {
        if (a()) {
            return a.a().b();
        }
        return null;
    }

    @Deprecated
    public static void getUpdateApk(ResultCallback<File> resultCallback) {
        if (a()) {
            a.a().a(resultCallback);
        } else {
            resultCallback.onResult(null, Error.fromInner(cy.a.NOT_INIT));
        }
    }

    public static String getVersion() {
        return "2.9.1";
    }

    public static boolean getWakeUp(Intent intent, AppWakeUpListener appWakeUpListener) {
        if (!a() || !OpenInstallHelper.isSchemeWakeup(intent)) {
            return false;
        }
        a.a().a(intent, appWakeUpListener);
        return true;
    }

    public static void getWakeUpAlwaysCallback(Intent intent, AppWakeUpListener appWakeUpListener) {
        if (!a()) {
            appWakeUpListener.onWakeUpFinish(null, Error.fromInner(cy.a.NOT_INIT));
        } else if (OpenInstallHelper.isSchemeWakeup(intent)) {
            a.a().a(intent, appWakeUpListener);
        } else {
            appWakeUpListener.onWakeUpFinish(null, Error.fromInner(cy.a.INVALID_INTENT));
        }
    }

    public static boolean getWakeUpYYB(Activity activity, Intent intent, AppWakeUpListener appWakeUpListener) {
        if (!a()) {
            return false;
        }
        if (OpenInstallHelper.isSchemeWakeup(intent)) {
            a.a().a(intent, appWakeUpListener);
            return true;
        }
        if (!OpenInstallHelper.isLauncherFromYYB(activity, intent)) {
            return false;
        }
        a.a().a(appWakeUpListener);
        return true;
    }

    public static void getWakeUpYYBAlwaysCallback(Activity activity, Intent intent, AppWakeUpListener appWakeUpListener) {
        if (!a()) {
            appWakeUpListener.onWakeUpFinish(null, Error.fromInner(cy.a.NOT_INIT));
            return;
        }
        if (OpenInstallHelper.isSchemeWakeup(intent)) {
            a.a().a(intent, appWakeUpListener);
        } else if (OpenInstallHelper.isLauncherFromYYB(activity, intent)) {
            a.a().a(appWakeUpListener);
        } else {
            appWakeUpListener.onWakeUpFinish(null, Error.fromInner(cy.a.INVALID_INTENT));
        }
    }

    public static void init(Context context) {
        init(context, Configuration.getDefault());
    }

    public static void init(Context context, Configuration configuration) {
        String strA = ea.a(context);
        if (TextUtils.isEmpty(strA)) {
            throw new IllegalArgumentException("请在AndroidManifest.xml中配置OpenInstall提供的AppKey");
        }
        init(context, strA, configuration);
    }

    public static void init(Context context, String str) {
        init(context, str, Configuration.getDefault());
    }

    public static void init(Context context, String str, Configuration configuration) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        WeakReference<Activity> weakReference = context instanceof Activity ? new WeakReference<>((Activity) context) : null;
        synchronized (OpenInstall.class) {
            if (!a) {
                if (ec.a) {
                    ec.b("未提前调用 preInit，可能导致统计数据不准确。", new Object[0]);
                }
                preInit(context, str);
            }
            if (!b) {
                a.a().a(configuration, weakReference, jCurrentTimeMillis);
                b = true;
            }
        }
    }

    public static void preInit(Context context) {
        String strA = ea.a(context);
        if (TextUtils.isEmpty(strA)) {
            throw new IllegalArgumentException("请在AndroidManifest.xml中配置OpenInstall提供的AppKey");
        }
        preInit(context, strA);
    }

    public static void preInit(Context context, String str) {
        if (context == null) {
            throw new IllegalArgumentException("context不能为空");
        }
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("请前往OpenInstall控制台的 “Android集成” -> “Android应用配置” 中获取AppKey");
        }
        if (ec.a) {
            ec.a("SDK Version : " + getVersion(), new Object[0]);
        }
        as.a().a(context.getApplicationContext());
        as.a().a(str);
        synchronized (OpenInstall.class) {
            if (!a) {
                a.a().c();
                a = true;
            }
        }
    }

    public static void reportEffectPoint(String str, long j) {
        if (a()) {
            a.a().a(str, j);
        }
    }

    public static void reportEffectPoint(String str, long j, Map<String, String> map) {
        if (a()) {
            a.a().a(str, j, map);
        }
    }

    public static void reportRegister() {
        if (a()) {
            a.a().d();
        }
    }

    public static void reportShare(String str, SharePlatform sharePlatform, ResultCallback<Void> resultCallback) {
        reportShare(str, sharePlatform.name(), resultCallback);
    }

    public static void reportShare(String str, String str2, ResultCallback<Void> resultCallback) {
        if (a()) {
            a.a().a(str, str2, resultCallback);
        } else {
            resultCallback.onResult(null, Error.fromInner(cy.a.NOT_INIT));
        }
    }

    @Deprecated
    public static void serialEnabled(boolean z) {
        as.a().b(Boolean.valueOf(z));
    }

    public static void setChannel(String str) {
        as.a().b(str);
    }

    public static void setDebug(boolean z) {
        ec.a = z;
    }

    public static void setTrackData(ClipData clipData) {
        as.a().a(clipData);
        as.a().a((Boolean) false);
    }
}
