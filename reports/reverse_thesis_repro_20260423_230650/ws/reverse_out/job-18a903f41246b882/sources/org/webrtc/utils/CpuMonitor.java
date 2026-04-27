package org.webrtc.utils;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.SystemClock;
import android.util.Log;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class CpuMonitor {
    private static final int CPU_STAT_LOG_PERIOD_MS = 6000;
    private static final int CPU_STAT_SAMPLE_PERIOD_MS = 2000;
    private static final int MOVING_AVERAGE_SAMPLES = 5;
    private static final String TAG = "CpuMonitor";
    private int actualCpusPresent;
    private final Context appContext;
    private long[] cpuFreqMax;
    private boolean cpuOveruse;
    private int cpusPresent;
    private double[] curFreqScales;
    private String[] curPath;
    private ScheduledExecutorService executor;
    private final MovingAverage frequencyScale;
    private boolean initialized;
    private ProcStat lastProcStat;
    private long lastStatLogTimeMs;
    private String[] maxPath;
    private final MovingAverage systemCpuUsage;
    private final MovingAverage totalCpuUsage;
    private final MovingAverage userCpuUsage;

    private static class ProcStat {
        final long idleTime;
        final long systemTime;
        final long userTime;

        ProcStat(long userTime, long systemTime, long idleTime) {
            this.userTime = userTime;
            this.systemTime = systemTime;
            this.idleTime = idleTime;
        }
    }

    private static class MovingAverage {
        private double[] circBuffer;
        private int circBufferIndex;
        private double currentValue;
        private final int size;
        private double sum;

        public MovingAverage(int size) {
            if (size <= 0) {
                throw new AssertionError("Size value in MovingAverage ctor should be positive.");
            }
            this.size = size;
            this.circBuffer = new double[size];
        }

        public void reset() {
            Arrays.fill(this.circBuffer, FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE);
            this.circBufferIndex = 0;
            this.sum = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
            this.currentValue = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        }

        public void addValue(double value) {
            double d = this.sum;
            double[] dArr = this.circBuffer;
            int i = this.circBufferIndex;
            double d2 = d - dArr[i];
            this.sum = d2;
            int i2 = i + 1;
            this.circBufferIndex = i2;
            dArr[i] = value;
            this.currentValue = value;
            this.sum = d2 + value;
            if (i2 >= this.size) {
                this.circBufferIndex = 0;
            }
        }

        public double getCurrent() {
            return this.currentValue;
        }

        public double getAverage() {
            return this.sum / ((double) this.size);
        }
    }

    public CpuMonitor(Context context) {
        Log.d(TAG, "CpuMonitor ctor.");
        this.appContext = context.getApplicationContext();
        this.userCpuUsage = new MovingAverage(5);
        this.systemCpuUsage = new MovingAverage(5);
        this.totalCpuUsage = new MovingAverage(5);
        this.frequencyScale = new MovingAverage(5);
        this.lastStatLogTimeMs = SystemClock.elapsedRealtime();
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
        resetStat();
        scheduleCpuUtilizationTask();
    }

    public synchronized void reset() {
        if (this.executor != null) {
            Log.d(TAG, "reset");
            resetStat();
            this.cpuOveruse = false;
        }
    }

    public synchronized int getCpuUsageCurrent() {
        return doubleToPercent(this.userCpuUsage.getCurrent() + this.systemCpuUsage.getCurrent());
    }

    public synchronized int getCpuUsageAverage() {
        return doubleToPercent(this.userCpuUsage.getAverage() + this.systemCpuUsage.getAverage());
    }

    public synchronized int getFrequencyScaleAverage() {
        return doubleToPercent(this.frequencyScale.getAverage());
    }

    private void scheduleCpuUtilizationTask() {
        ScheduledExecutorService scheduledExecutorService = this.executor;
        if (scheduledExecutorService != null) {
            scheduledExecutorService.shutdownNow();
            this.executor = null;
        }
        ScheduledExecutorService scheduledExecutorServiceNewSingleThreadScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        this.executor = scheduledExecutorServiceNewSingleThreadScheduledExecutor;
        scheduledExecutorServiceNewSingleThreadScheduledExecutor.scheduleAtFixedRate(new Runnable() { // from class: org.webrtc.utils.CpuMonitor.1
            @Override // java.lang.Runnable
            public void run() {
                CpuMonitor.this.cpuUtilizationTask();
            }
        }, 0L, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void cpuUtilizationTask() {
        boolean cpuMonitorAvailable = sampleCpuUtilization();
        if (cpuMonitorAvailable && SystemClock.elapsedRealtime() - this.lastStatLogTimeMs >= 6000) {
            this.lastStatLogTimeMs = SystemClock.elapsedRealtime();
            String statString = getStatString();
            Log.d(TAG, statString);
        }
    }

    private void init() {
        try {
            FileReader fin = new FileReader("/sys/devices/system/cpu/present");
            try {
                BufferedReader reader = new BufferedReader(fin);
                Scanner scanner = new Scanner(reader).useDelimiter("[-\n]");
                scanner.nextInt();
                this.cpusPresent = scanner.nextInt() + 1;
                scanner.close();
            } catch (Exception e) {
                Log.e(TAG, "Cannot do CPU stats due to /sys/devices/system/cpu/present parsing problem");
            } finally {
                fin.close();
            }
        } catch (FileNotFoundException e2) {
            Log.e(TAG, "Cannot do CPU stats since /sys/devices/system/cpu/present is missing");
        } catch (IOException e3) {
            Log.e(TAG, "Error closing file");
        }
        int i = this.cpusPresent;
        this.cpuFreqMax = new long[i];
        this.maxPath = new String[i];
        this.curPath = new String[i];
        this.curFreqScales = new double[i];
        for (int i2 = 0; i2 < this.cpusPresent; i2++) {
            this.cpuFreqMax[i2] = 0;
            this.curFreqScales[i2] = 0.0d;
            this.maxPath[i2] = "/sys/devices/system/cpu/cpu" + i2 + "/cpufreq/cpuinfo_max_freq";
            this.curPath[i2] = "/sys/devices/system/cpu/cpu" + i2 + "/cpufreq/scaling_cur_freq";
        }
        this.lastProcStat = new ProcStat(0L, 0L, 0L);
        resetStat();
        this.initialized = true;
    }

    private synchronized void resetStat() {
        this.userCpuUsage.reset();
        this.systemCpuUsage.reset();
        this.totalCpuUsage.reset();
        this.frequencyScale.reset();
        this.lastStatLogTimeMs = SystemClock.elapsedRealtime();
    }

    private int getBatteryLevel() {
        Intent intent = this.appContext.registerReceiver(null, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
        int batteryScale = intent.getIntExtra("scale", 100);
        if (batteryScale <= 0) {
            return 0;
        }
        int batteryLevel = (int) ((intent.getIntExtra("level", 0) * 100.0f) / batteryScale);
        return batteryLevel;
    }

    private synchronized boolean sampleCpuUtilization() {
        long lastSeenMaxFreq = 0;
        long cpuFreqCurSum = 0;
        long cpuFreqMaxSum = 0;
        if (!this.initialized) {
            init();
        }
        if (this.cpusPresent == 0) {
            return false;
        }
        this.actualCpusPresent = 0;
        for (int i = 0; i < this.cpusPresent; i++) {
            this.curFreqScales[i] = 0.0d;
            if (this.cpuFreqMax[i] == 0) {
                long cpufreqMax = readFreqFromFile(this.maxPath[i]);
                if (cpufreqMax > 0) {
                    Log.d(TAG, "Core " + i + ". Max frequency: " + cpufreqMax);
                    lastSeenMaxFreq = cpufreqMax;
                    this.cpuFreqMax[i] = cpufreqMax;
                    this.maxPath[i] = null;
                }
            } else {
                lastSeenMaxFreq = this.cpuFreqMax[i];
            }
            long cpuFreqCur = readFreqFromFile(this.curPath[i]);
            if (cpuFreqCur != 0 || lastSeenMaxFreq != 0) {
                if (cpuFreqCur > 0) {
                    this.actualCpusPresent++;
                }
                cpuFreqCurSum += cpuFreqCur;
                cpuFreqMaxSum += lastSeenMaxFreq;
                if (lastSeenMaxFreq > 0) {
                    this.curFreqScales[i] = cpuFreqCur / lastSeenMaxFreq;
                }
            }
        }
        if (cpuFreqCurSum == 0 || cpuFreqMaxSum == 0) {
            Log.e(TAG, "Could not read max or current frequency for any CPU");
            return false;
        }
        double currentFrequencyScale = cpuFreqCurSum / cpuFreqMaxSum;
        if (this.frequencyScale.getCurrent() > FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
            currentFrequencyScale = (this.frequencyScale.getCurrent() + currentFrequencyScale) * 0.5d;
        }
        ProcStat procStat = readProcStat();
        if (procStat == null) {
            return false;
        }
        long diffUserTime = procStat.userTime - this.lastProcStat.userTime;
        long diffSystemTime = procStat.systemTime - this.lastProcStat.systemTime;
        long diffIdleTime = procStat.idleTime - this.lastProcStat.idleTime;
        long allTime = diffUserTime + diffSystemTime + diffIdleTime;
        if (currentFrequencyScale == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE || allTime == 0) {
            return false;
        }
        this.frequencyScale.addValue(currentFrequencyScale);
        double currentUserCpuUsage = diffUserTime / allTime;
        this.userCpuUsage.addValue(currentUserCpuUsage);
        double currentSystemCpuUsage = diffSystemTime / allTime;
        this.systemCpuUsage.addValue(currentSystemCpuUsage);
        double currentTotalCpuUsage = (currentUserCpuUsage + currentSystemCpuUsage) * currentFrequencyScale;
        this.totalCpuUsage.addValue(currentTotalCpuUsage);
        this.lastProcStat = procStat;
        return true;
    }

    private int doubleToPercent(double d) {
        return (int) ((100.0d * d) + 0.5d);
    }

    public synchronized String getStatString() {
        return "CPU \nUser: " + doubleToPercent(this.userCpuUsage.getCurrent()) + "/" + doubleToPercent(this.userCpuUsage.getAverage()) + "\nSystem: " + doubleToPercent(this.systemCpuUsage.getCurrent()) + "/" + doubleToPercent(this.systemCpuUsage.getAverage()) + "\nFreq: " + doubleToPercent(this.frequencyScale.getCurrent()) + "/" + doubleToPercent(this.frequencyScale.getAverage()) + "\nTotal usage: " + doubleToPercent(this.totalCpuUsage.getCurrent()) + "/" + doubleToPercent(this.totalCpuUsage.getAverage());
    }

    private long readFreqFromFile(String fileName) {
        long number = 0;
        try {
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            try {
                String line = reader.readLine();
                number = parseLong(line);
                reader.close();
            } catch (Throwable th) {
                reader.close();
                throw th;
            }
        } catch (FileNotFoundException e) {
        } catch (IOException e2) {
        }
        return number;
    }

    private static long parseLong(String value) {
        try {
            long number = Long.parseLong(value);
            return number;
        } catch (NumberFormatException e) {
            Log.e(TAG, "parseLong error.", e);
            return 0L;
        }
    }

    private ProcStat readProcStat() {
        long userTime = 0;
        long systemTime = 0;
        long idleTime = 0;
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/stat"));
            try {
                String line = reader.readLine();
                String[] lines = line.split("\\s+");
                int length = lines.length;
                if (length >= 5) {
                    long userTime2 = parseLong(lines[1]);
                    userTime = userTime2 + parseLong(lines[2]);
                    systemTime = parseLong(lines[3]);
                    idleTime = parseLong(lines[4]);
                }
                if (length >= 8) {
                    userTime += parseLong(lines[5]);
                    systemTime = systemTime + parseLong(lines[6]) + parseLong(lines[7]);
                }
                return new ProcStat(userTime, systemTime, idleTime);
            } catch (Exception e) {
                Log.e(TAG, "Problems parsing /proc/stat", e);
                return null;
            } finally {
                reader.close();
            }
        } catch (FileNotFoundException e2) {
            Log.e(TAG, "Cannot open /proc/stat for reading");
            return null;
        } catch (IOException e3) {
            Log.e(TAG, "Problems reading /proc/stat");
            return null;
        } catch (Throwable th) {
            Log.e(TAG, "Unknown error");
            return null;
        }
    }
}
