package com.just.agentweb;

import android.content.Context;
import android.os.AsyncTask;
import android.os.Build;
import android.text.TextUtils;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import java.io.File;

/* JADX INFO: loaded from: classes3.dex */
public class AgentWebConfig {
    static String AGENTWEB_FILE_PATH = null;
    public static final String AGENTWEB_NAME = "AgentWeb";
    public static final String AGENTWEB_VERSION = "AgentWeb/5.0.0";
    private static volatile boolean IS_INITIALIZED = false;
    static final boolean IS_KITKAT_OR_BELOW_KITKAT;
    public static int MAX_FILE_LENGTH = 0;
    private static final String TAG;
    public static final int WEBVIEW_AGENTWEB_SAFE_TYPE = 2;
    public static final int WEBVIEW_CUSTOM_TYPE = 3;
    public static final int WEBVIEW_DEFAULT_TYPE = 1;
    static final String FILE_CACHE_PATH = "agentweb-cache";
    static final String AGENTWEB_CACHE_PATCH = File.separator + FILE_CACHE_PATH;
    public static boolean DEBUG = false;

    static {
        IS_KITKAT_OR_BELOW_KITKAT = Build.VERSION.SDK_INT <= 19;
        IS_INITIALIZED = false;
        TAG = AgentWebConfig.class.getSimpleName();
        MAX_FILE_LENGTH = 5242880;
    }

    public static String getCookiesByUrl(String url) {
        if (CookieManager.getInstance() == null) {
            return null;
        }
        return CookieManager.getInstance().getCookie(url);
    }

    public static void debug() {
        DEBUG = true;
        if (Build.VERSION.SDK_INT >= 19) {
            WebView.setWebContentsDebuggingEnabled(true);
        }
    }

    public static void removeExpiredCookies() {
        CookieManager mCookieManager = CookieManager.getInstance();
        if (mCookieManager != null) {
            mCookieManager.removeExpiredCookie();
            toSyncCookies();
        }
    }

    public static void removeAllCookies() {
        removeAllCookies(null);
    }

    public static void removeSessionCookies() {
        removeSessionCookies(null);
    }

    public static void syncCookie(String url, String cookies) {
        CookieManager mCookieManager = CookieManager.getInstance();
        if (mCookieManager != null) {
            mCookieManager.setCookie(url, cookies);
            toSyncCookies();
        }
    }

    public static void removeSessionCookies(ValueCallback<Boolean> callback) {
        if (callback == null) {
            callback = getDefaultIgnoreCallback();
        }
        if (CookieManager.getInstance() == null) {
            callback.onReceiveValue(new Boolean(false));
            return;
        }
        if (Build.VERSION.SDK_INT < 21) {
            CookieManager.getInstance().removeSessionCookie();
            toSyncCookies();
            callback.onReceiveValue(new Boolean(true));
        } else {
            CookieManager.getInstance().removeSessionCookies(callback);
            toSyncCookies();
        }
    }

    public static String getCachePath(Context context) {
        return context.getCacheDir().getAbsolutePath() + AGENTWEB_CACHE_PATCH;
    }

    public static String getExternalCachePath(Context context) {
        return AgentWebUtils.getAgentWebFilePath(context);
    }

    public static void removeAllCookies(ValueCallback<Boolean> callback) {
        if (callback == null) {
            callback = getDefaultIgnoreCallback();
        }
        if (Build.VERSION.SDK_INT < 21) {
            CookieManager.getInstance().removeAllCookie();
            toSyncCookies();
            callback.onReceiveValue(Boolean.valueOf(!CookieManager.getInstance().hasCookies()));
        } else {
            CookieManager.getInstance().removeAllCookies(callback);
            toSyncCookies();
        }
    }

    public static synchronized void clearDiskCache(Context context) {
        try {
            AgentWebUtils.clearCacheFolder(new File(getCachePath(context)), 0);
            String path = getExternalCachePath(context);
            if (!TextUtils.isEmpty(path)) {
                File mFile = new File(path);
                AgentWebUtils.clearCacheFolder(mFile, 0);
            }
        } catch (Throwable throwable) {
            if (LogUtils.isDebug()) {
                throwable.printStackTrace();
            }
        }
    }

    static synchronized void initCookiesManager(Context context) {
        if (!IS_INITIALIZED) {
            createCookiesSyncInstance(context);
            IS_INITIALIZED = true;
        }
    }

    private static void createCookiesSyncInstance(Context context) {
        if (Build.VERSION.SDK_INT < 21) {
            CookieSyncManager.createInstance(context);
        }
    }

    private static void toSyncCookies() {
        if (Build.VERSION.SDK_INT < 21) {
            CookieSyncManager.getInstance().sync();
        } else {
            AsyncTask.THREAD_POOL_EXECUTOR.execute(new Runnable() { // from class: com.just.agentweb.AgentWebConfig.1
                @Override // java.lang.Runnable
                public void run() {
                    CookieManager.getInstance().flush();
                }
            });
        }
    }

    static String getDatabasesCachePath(Context context) {
        return context.getApplicationContext().getDir("database", 0).getPath();
    }

    private static ValueCallback<Boolean> getDefaultIgnoreCallback() {
        return new ValueCallback<Boolean>() { // from class: com.just.agentweb.AgentWebConfig.2
            @Override // android.webkit.ValueCallback
            public void onReceiveValue(Boolean ignore) {
                LogUtils.i(AgentWebConfig.TAG, "removeExpiredCookies:" + ignore);
            }
        };
    }
}
