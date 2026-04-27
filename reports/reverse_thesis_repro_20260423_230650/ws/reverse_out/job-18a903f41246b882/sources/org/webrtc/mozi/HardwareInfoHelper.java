package org.webrtc.mozi;

import android.app.ActivityManager;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.os.Build;
import android.os.Debug;
import android.os.Process;
import com.king.zxing.util.LogUtils;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;

/* JADX INFO: loaded from: classes3.dex */
public class HardwareInfoHelper {
    private static final String TAG = "HardwareInfoHelper";
    private static ActivityManager sActivityManager;
    private static int[] sMemPid;
    private static int sMyPid;
    private static long sMaxAppMemory = 0;
    private static long sTotalMemory = 0;

    static native String nativeHardwareInfoGetCpuBrand();

    static native String nativeHardwareInfoGetCpuUarch();

    static native void nativeHardwareInfoPerformanceLevelStats(long j);

    static native void nativeHardwareInfoStarStats(long j);

    static native void nativeHardwareInfoStopStats(long j);

    public static void startStats(long nativeFactoryPtr) {
        Logging.d(TAG, "HardwareInfoHelper startStats");
        sActivityManager = (ActivityManager) ContextUtils.getApplicationContext().getSystemService("activity");
        int iMyPid = Process.myPid();
        sMyPid = iMyPid;
        sMemPid = new int[]{iMyPid};
        nativeHardwareInfoStarStats(nativeFactoryPtr);
    }

    public static void stopStats(long nativeFactoryPtr) {
        Logging.d(TAG, "HardwareInfoHelper stopStats");
        nativeHardwareInfoStopStats(nativeFactoryPtr);
    }

    public static void performanceLevelStats(long nativeFactoryPtr) {
        Logging.d(TAG, "HardwareInfoHelper performanceLevelStats");
        nativeHardwareInfoPerformanceLevelStats(nativeFactoryPtr);
    }

    public static String getCpuBrand() {
        String cpuInfo = nativeHardwareInfoGetCpuBrand();
        return cpuInfo;
    }

    public static String getCpuUarch() {
        String cpuUarch = nativeHardwareInfoGetCpuUarch();
        return cpuUarch;
    }

    public static boolean isSupported() {
        return Build.VERSION.SDK_INT < 26 && ContextUtils.getApplicationContext() != null;
    }

    public static long getAppMemorySize() {
        ActivityManager activityManager = sActivityManager;
        if (activityManager == null) {
            return 0L;
        }
        try {
            Debug.MemoryInfo memoryInfo = activityManager.getProcessMemoryInfo(sMemPid)[0];
            return memoryInfo.getTotalPss() / 1024;
        } catch (Exception e) {
            return 0L;
        }
    }

    public static long getSystemMemorySize() {
        if (sActivityManager == null) {
            return 0L;
        }
        try {
            ActivityManager.MemoryInfo outInfo = new ActivityManager.MemoryInfo();
            sActivityManager.getMemoryInfo(outInfo);
            long usedMem = outInfo.totalMem - outInfo.availMem;
            return usedMem / 1048576;
        } catch (Exception e) {
            return 0L;
        }
    }

    public static long getTotalMemory() {
        long j = sTotalMemory;
        if (j > 0) {
            return j;
        }
        String memTotal = "";
        FileReader fr = null;
        BufferedReader localBufferedReader = null;
        try {
            fr = new FileReader("/proc/meminfo");
            localBufferedReader = new BufferedReader(fr, 8192);
        } catch (Exception e) {
        } catch (Throwable th) {
            closeQuietly((Reader) localBufferedReader);
            closeQuietly((Reader) fr);
            throw th;
        }
        while (true) {
            String readTemp = localBufferedReader.readLine();
            if (readTemp == null) {
                break;
            }
            if (readTemp.contains("MemTotal")) {
                String[] total = readTemp.split(LogUtils.COLON);
                memTotal = total[1].trim();
            }
            closeQuietly((Reader) localBufferedReader);
            closeQuietly((Reader) fr);
            return sTotalMemory;
        }
        String[] memKb = memTotal.split(" ");
        String memTotal2 = memKb[0].trim();
        sTotalMemory = Long.parseLong(memTotal2) / 1024;
        closeQuietly((Reader) localBufferedReader);
        closeQuietly((Reader) fr);
        return sTotalMemory;
    }

    public static long getAppMaxMemory() {
        try {
            if (sMaxAppMemory <= 0) {
                sMaxAppMemory = Runtime.getRuntime().maxMemory() / 1024;
            }
            return sMaxAppMemory;
        } catch (Exception e) {
            return 0L;
        }
    }

    public static String getBrand() {
        return Build.BRAND;
    }

    public static String getDeviceModel() {
        return Build.MODEL;
    }

    public static String getOSVersion() {
        return Build.VERSION.RELEASE;
    }

    public static String getAv1Decoders() {
        StringBuilder av1Decoders = new StringBuilder();
        if (Build.VERSION.SDK_INT < 21) {
            av1Decoders.append("SDK not support");
        } else {
            int codecCount = MediaCodecList.getCodecCount();
            for (int i = 0; i < codecCount; i++) {
                MediaCodecInfo codecInfo = MediaCodecList.getCodecInfoAt(i);
                if (!codecInfo.isEncoder()) {
                    String[] supportedTypes = codecInfo.getSupportedTypes();
                    int length = supportedTypes.length;
                    int i2 = 0;
                    while (true) {
                        if (i2 < length) {
                            String type = supportedTypes[i2];
                            if (!"video/av01".equalsIgnoreCase(type)) {
                                i2++;
                            } else {
                                av1Decoders.append(codecInfo.getName());
                                av1Decoders.append(",");
                                break;
                            }
                        }
                    }
                }
            }
            int i3 = av1Decoders.length();
            if (i3 == 0) {
                av1Decoders.append("No AV1 decoders");
            }
        }
        return av1Decoders.toString();
    }

    private static void closeQuietly(Reader input) {
        closeQuietly((Closeable) input);
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
            }
        }
    }
}
