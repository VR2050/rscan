package com.csm.shield;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.provider.Settings;
import android.util.JsonWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class GameShield {
    public static final int DEBUG = 0;
    public static final int ERROR = 3;
    public static final int FATAL = 4;
    public static final int INFO = 1;
    public static final int WARN = 2;
    private static String brand;
    private static String build_version;
    private static Context context;
    private static String device_id;
    private static String fs_dir;
    private static FunctionPointer functionPointer;
    private static boolean is_emulator;
    private static String model;
    private static ScheduledExecutorService scheduler;

    public static native int GetSDKInitResult();

    public static native Object getGlobalContext();

    public static native int getListenPort(int i);

    public static native int getPorts(int[][] iArr, int i, int i2);

    public static native int sdkInit(String str, String str2, String str3);

    public static native int sdkInitAsync(String str, String str2, String str3);

    public static native void setDevInfo(String str);

    static {
        System.loadLibrary("shield");
        functionPointer = null;
        context = null;
        device_id = null;
        fs_dir = null;
        is_emulator = isEmulator();
        brand = Build.BRAND;
        model = Build.MODEL;
        build_version = Build.VERSION.RELEASE;
    }

    private static String getCacheDir() {
        if (context == null) {
            context = (Context) getGlobalContext();
        }
        return context.getCacheDir().toString();
    }

    private static String getDeviceID() {
        if (context == null) {
            context = (Context) getGlobalContext();
        }
        return Settings.System.getString(context.getContentResolver(), "android_id");
    }

    public static int sdkInitEx(String app_key, FunctionPointer fp) {
        functionPointer = fp;
        device_id = getDeviceID();
        fs_dir = getCacheDir();
        startNetworkCheckTimer();
        return sdkInit(app_key, device_id, fs_dir);
    }

    public static int sdkInitExAsync(String app_key) {
        device_id = getDeviceID();
        String cacheDir = getCacheDir();
        fs_dir = cacheDir;
        return sdkInitAsync(app_key, device_id, cacheDir);
    }

    public static int sdkInitEx(String appid) {
        return sdkInitEx(appid, null);
    }

    public static void callback(int status) {
        FunctionPointer functionPointer2 = functionPointer;
        if (functionPointer2 != null) {
            functionPointer2.Run(status);
        }
    }

    public static int getNetworkType() {
        Network activeNetwork;
        NetworkCapabilities capabilities;
        if (context == null) {
            context = (Context) getGlobalContext();
        }
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService("connectivity");
        if (cm == null || (activeNetwork = cm.getActiveNetwork()) == null || (capabilities = cm.getNetworkCapabilities(activeNetwork)) == null) {
            return 3;
        }
        if (capabilities.hasTransport(1)) {
            return 1;
        }
        if (!capabilities.hasTransport(0)) {
            return 3;
        }
        return 2;
    }

    public static boolean isEmulator() {
        boolean isX86 = false;
        if (Build.VERSION.SDK_INT >= 21) {
            String[] strArr = Build.SUPPORTED_ABIS;
            int length = strArr.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                String abi = strArr[i];
                if (!abi.contains("x86")) {
                    i++;
                } else {
                    isX86 = true;
                    break;
                }
            }
        } else {
            isX86 = Build.CPU_ABI.contains("x86") || Build.CPU_ABI2.contains("x86");
        }
        String fingerprint = Build.FINGERPRINT;
        String model2 = Build.MODEL;
        String manufacturer = Build.MANUFACTURER;
        String brand2 = Build.BRAND;
        String device = Build.DEVICE;
        String product = Build.PRODUCT;
        String hardware = Build.HARDWARE;
        boolean hasEmulatorFeature = fingerprint.contains("generic") || fingerprint.contains("unknown") || model2.contains("google_sdk") || model2.contains("Emulator") || model2.contains("Android SDK built for x86") || manufacturer.contains("Genymotion") || brand2.contains("generic") || device.contains("generic") || product.contains("sdk") || product.contains("vbox86p") || product.contains("emulator") || product.contains("simulator") || hardware.contains("goldfish") || hardware.contains("ranchu");
        return isX86 || hasEmulatorFeature;
    }

    public static void buildAndSetDevInfo(int netType, boolean isEmulator) {
        StringWriter stringWriter = new StringWriter();
        JsonWriter jsonWriter = new JsonWriter(stringWriter);
        try {
            try {
                try {
                    jsonWriter.beginObject();
                    jsonWriter.name("net_type").value(netType);
                    jsonWriter.name("emulator").value(isEmulator);
                    jsonWriter.name("brand").value(brand);
                    jsonWriter.name("model").value(model);
                    jsonWriter.name("api_version").value(build_version);
                    jsonWriter.endObject();
                    setDevInfo(stringWriter.toString());
                    jsonWriter.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } catch (IOException e2) {
                e2.printStackTrace();
                jsonWriter.close();
            }
        } catch (Throwable th) {
            try {
                jsonWriter.close();
            } catch (IOException e3) {
                e3.printStackTrace();
            }
            throw th;
        }
    }

    public static void startNetworkCheckTimer() {
        if (scheduler == null) {
            ScheduledExecutorService scheduledExecutorServiceNewSingleThreadScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
            scheduler = scheduledExecutorServiceNewSingleThreadScheduledExecutor;
            scheduledExecutorServiceNewSingleThreadScheduledExecutor.scheduleAtFixedRate(new Runnable() { // from class: com.csm.shield.GameShield.1
                @Override // java.lang.Runnable
                public void run() {
                    GameShield.buildAndSetDevInfo(GameShield.getNetworkType(), GameShield.is_emulator);
                }
            }, 0L, 30L, TimeUnit.SECONDS);
        }
    }
}
