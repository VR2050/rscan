package com.snail.antifake.deviceid;

import android.app.ActivityManager;
import android.app.Application;
import android.os.Process;
import java.lang.Thread;

/* JADX INFO: loaded from: classes3.dex */
public class CrashHandler implements Thread.UncaughtExceptionHandler {
    private Application mApplication;

    public CrashHandler(Application application) {
        this.mApplication = application;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public void uncaughtException(Thread thread, Throwable ex) {
        Process.killProcess(Process.myPid());
        ActivityManager manager = (ActivityManager) this.mApplication.getSystemService("activity");
        for (ActivityManager.RunningAppProcessInfo processInfo : manager.getRunningAppProcesses()) {
            if (processInfo.pid == Process.myPid()) {
                if (!this.mApplication.getPackageName().equals(processInfo.processName)) {
                    Process.killProcess(Process.myPid());
                    return;
                }
                return;
            }
        }
    }
}
