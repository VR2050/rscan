package org.webrtc.utils;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Debug;
import android.util.Log;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.king.zxing.util.LogUtils;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class MemoryMonitor {
    private static final int CPU_STAT_SAMPLE_PERIOD_MS = 2000;
    private static final String TAG = MemoryMonitor.class.getSimpleName();
    private WeakReference<Context> contextWeakReference;
    private ScheduledExecutorService executor;
    private long free_memory;
    private long total_memory;
    private long userMemory;

    public MemoryMonitor(Context context) {
        this.contextWeakReference = new WeakReference<>(context);
    }

    public void pause() {
        if (this.executor != null) {
            Log.d(TAG, "pause");
            this.executor.shutdownNow();
            this.executor = null;
        }
    }

    public void resume() {
        Log.d(TAG, "resume");
        this.total_memory = 0L;
        this.free_memory = 0L;
        this.userMemory = 0L;
        scheduleMemoryUtilizationTask();
    }

    private long getTotalMemory() {
        String memTotal = "";
        try {
            FileReader fr = new FileReader("/proc/meminfo");
            BufferedReader localBufferedReader = new BufferedReader(fr, 8192);
            while (true) {
                String readTemp = localBufferedReader.readLine();
                if (readTemp != null) {
                    if (readTemp.contains("MemTotal")) {
                        String[] total = readTemp.split(LogUtils.COLON);
                        memTotal = total[1].trim();
                    }
                } else {
                    localBufferedReader.close();
                    String[] memKb = memTotal.split(" ");
                    String memTotal2 = memKb[0].trim();
                    Log.d(TAG, "memTotal: " + memTotal2);
                    long memory = Long.parseLong(memTotal2);
                    return memory;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            return 0L;
        }
    }

    private long getFreeMemorySize(Context context) {
        ActivityManager.MemoryInfo outInfo = new ActivityManager.MemoryInfo();
        ActivityManager am = (ActivityManager) context.getSystemService("activity");
        am.getMemoryInfo(outInfo);
        long avaliMem = outInfo.availMem;
        return avaliMem / 1024;
    }

    private int getUserMemorySize(Context context) {
        ActivityManager am = (ActivityManager) context.getSystemService("activity");
        List<ActivityManager.RunningAppProcessInfo> pids = am.getRunningAppProcesses();
        int processid = 0;
        for (int i = 0; i < pids.size(); i++) {
            ActivityManager.RunningAppProcessInfo info = pids.get(i);
            if (info.processName.equalsIgnoreCase("com.aliyun.sophon.demo")) {
                processid = info.pid;
            }
        }
        int[] myMempid = {processid};
        Debug.MemoryInfo[] memoryInfo = am.getProcessMemoryInfo(myMempid);
        memoryInfo[0].getTotalSharedDirty();
        int memSize = memoryInfo[0].getTotalPss();
        return memSize;
    }

    public synchronized String getMemoryUsageCurrent() {
        String memory;
        memory = "Memory\nTotal_Memory:" + this.total_memory + "\nFree_Memory" + this.free_memory + "\nUserMemoryByPid" + this.userMemory;
        return memory;
    }

    public synchronized long getMemoryUsageCurrentByPid() {
        return this.userMemory;
    }

    private void scheduleMemoryUtilizationTask() {
        ScheduledExecutorService scheduledExecutorService = this.executor;
        if (scheduledExecutorService != null) {
            scheduledExecutorService.shutdownNow();
            this.executor = null;
        }
        ScheduledExecutorService scheduledExecutorServiceNewSingleThreadScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        this.executor = scheduledExecutorServiceNewSingleThreadScheduledExecutor;
        scheduledExecutorServiceNewSingleThreadScheduledExecutor.scheduleAtFixedRate(new Runnable() { // from class: org.webrtc.utils.MemoryMonitor.1
            @Override // java.lang.Runnable
            public void run() {
                MemoryMonitor.this.memoryUtilization();
            }
        }, 0L, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void memoryUtilization() {
        this.total_memory = getTotalMemory();
        this.free_memory = getFreeMemorySize(this.contextWeakReference.get());
        this.userMemory = getUserMemorySize(this.contextWeakReference.get());
    }
}
