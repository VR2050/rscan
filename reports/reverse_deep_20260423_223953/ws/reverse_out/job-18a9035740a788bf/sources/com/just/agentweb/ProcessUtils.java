package com.just.agentweb;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.os.Process;
import android.text.TextUtils;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
class ProcessUtils {
    ProcessUtils() {
    }

    static String getCurrentProcessName(Context context) {
        String name = getCurrentProcessNameByFile();
        if (!TextUtils.isEmpty(name)) {
            return name;
        }
        String name2 = getCurrentProcessNameByAms(context);
        return !TextUtils.isEmpty(name2) ? name2 : getCurrentProcessNameByReflect(context);
    }

    private static String getCurrentProcessNameByFile() {
        try {
            File file = new File("/proc/" + Process.myPid() + "/cmdline");
            BufferedReader mBufferedReader = new BufferedReader(new FileReader(file));
            String processName = mBufferedReader.readLine().trim();
            mBufferedReader.close();
            return processName;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private static String getCurrentProcessNameByAms(Context context) {
        List<ActivityManager.RunningAppProcessInfo> info;
        ActivityManager am = (ActivityManager) context.getSystemService("activity");
        if (am == null || (info = am.getRunningAppProcesses()) == null || info.size() == 0) {
            return "";
        }
        int pid = Process.myPid();
        for (ActivityManager.RunningAppProcessInfo aInfo : info) {
            if (aInfo.pid == pid && aInfo.processName != null) {
                return aInfo.processName;
            }
        }
        return "";
    }

    private static String getCurrentProcessNameByReflect(Context context) {
        try {
            Application app = (Application) context.getApplicationContext();
            Field loadedApkField = app.getClass().getField("mLoadedApk");
            loadedApkField.setAccessible(true);
            Object loadedApk = loadedApkField.get(app);
            Field activityThreadField = loadedApk.getClass().getDeclaredField("mActivityThread");
            activityThreadField.setAccessible(true);
            Object activityThread = activityThreadField.get(loadedApk);
            Method getProcessName = activityThread.getClass().getDeclaredMethod("getProcessName", new Class[0]);
            String processName = (String) getProcessName.invoke(activityThread, new Object[0]);
            return processName;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}
