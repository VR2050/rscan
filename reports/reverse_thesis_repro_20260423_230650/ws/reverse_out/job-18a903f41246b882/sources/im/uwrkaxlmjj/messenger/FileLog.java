package im.uwrkaxlmjj.messenger;

import android.util.Log;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.time.FastDateFormat;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.Locale;

/* JADX INFO: loaded from: classes2.dex */
public class FileLog {
    private static volatile FileLog Instance = null;
    private static final String tag = "tmessages";
    private boolean initied;
    private OutputStreamWriter streamWriter = null;
    private FastDateFormat dateFormat = null;
    private DispatchQueue logQueue = null;
    private File currentFile = null;
    private File networkFile = null;

    public static FileLog getInstance() {
        FileLog localInstance = Instance;
        if (localInstance == null) {
            synchronized (FileLog.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    FileLog fileLog = new FileLog();
                    localInstance = fileLog;
                    Instance = fileLog;
                }
            }
        }
        return localInstance;
    }

    private FileLog() {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        init();
    }

    public void init() {
        if (this.initied) {
            return;
        }
        this.dateFormat = FastDateFormat.getInstance("dd_MM_yyyy_HH_mm_ss", Locale.US);
        try {
            File sdCard = ApplicationLoader.applicationContext.getExternalFilesDir(null);
            if (sdCard == null) {
                return;
            }
            File dir = new File(sdCard.getAbsolutePath() + "/logs");
            dir.mkdirs();
            this.currentFile = new File(dir, this.dateFormat.format(System.currentTimeMillis()) + ".txt");
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            this.logQueue = new DispatchQueue("logQueue");
            this.currentFile.createNewFile();
            FileOutputStream stream = new FileOutputStream(this.currentFile);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(stream);
            this.streamWriter = outputStreamWriter;
            outputStreamWriter.write("-----start log " + this.dateFormat.format(System.currentTimeMillis()) + "-----\n");
            this.streamWriter.flush();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        this.initied = true;
    }

    private static void ensureInitied() {
        getInstance().init();
    }

    public static String getNetworkLogPath() {
        if (!BuildVars.LOGS_ENABLED) {
            return "";
        }
        try {
            File sdCard = ApplicationLoader.applicationContext.getExternalFilesDir(null);
            if (sdCard == null) {
                return "";
            }
            File dir = new File(sdCard.getAbsolutePath() + "/logs");
            dir.mkdirs();
            getInstance().networkFile = new File(dir, getInstance().dateFormat.format(System.currentTimeMillis()) + "_net.txt");
            return getInstance().networkFile.getAbsolutePath();
        } catch (Throwable e) {
            e.printStackTrace();
            return "";
        }
    }

    public static void e(final String message, final Throwable exception) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.e(tag, message, exception);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$2ruuYO3BysJQtRJ3ZlSiflVSWmY
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$e$0(message, exception);
                }
            });
        }
    }

    static /* synthetic */ void lambda$e$0(String message, Throwable exception) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " E/tmessages: " + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.write(exception.toString());
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void e(final String message) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.e(tag, message);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$LSp6sSrrLfldyt6gxTJSvBjhmPI
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$e$1(message);
                }
            });
        }
    }

    static /* synthetic */ void lambda$e$1(String message) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " E/tmessages: " + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void e(final String tag2, final String message) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.e(tag2, message);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$HV1quAR0zxnkqPaSmUl0DzbTCJQ
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$e$2(tag2, message);
                }
            });
        }
    }

    static /* synthetic */ void lambda$e$2(String tag2, String message) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " E/" + tag2 + " :" + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void e(final String tag2, final String message, final Throwable exception) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.e(tag2, message, exception);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$T7uopjFuV27PFcHklKkgah193pI
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$e$3(tag2, message, exception);
                }
            });
        }
    }

    static /* synthetic */ void lambda$e$3(String tag2, String message, Throwable exception) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " E/" + tag2 + " :" + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.write(exception.toString());
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void e(final Throwable e) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        e.printStackTrace();
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$TFWRJ3J6cL5BMU8SlzGbiG9Hn6c
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$e$4(e);
                }
            });
        } else {
            e.printStackTrace();
        }
    }

    static /* synthetic */ void lambda$e$4(Throwable e) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " E/tmessages: " + e + ShellAdbUtils.COMMAND_LINE_END);
            StackTraceElement[] stack = e.getStackTrace();
            for (StackTraceElement stackTraceElement : stack) {
                getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " E/tmessages: " + stackTraceElement + ShellAdbUtils.COMMAND_LINE_END);
            }
            getInstance().streamWriter.flush();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }

    public static void d(final String message) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.d(tag, message);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$cPqwmn3OONu1B_9t9n8D573aOU0
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$d$5(message);
                }
            });
        }
    }

    static /* synthetic */ void lambda$d$5(String message) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " D/tmessages: " + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void d(final String tag2, final String message) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.d(tag2, message);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$3_ba5NUV3i4VZP_whTAaPZZtyRs
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$d$6(tag2, message);
                }
            });
        }
    }

    static /* synthetic */ void lambda$d$6(String tag2, String message) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " D/" + tag2 + " :" + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void w(final String message) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.w(tag, message);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$6j3yjmWtDYWo9y2mMcAAHfNkDtU
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$w$7(message);
                }
            });
        }
    }

    static /* synthetic */ void lambda$w$7(String message) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " W/tmessages: " + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void w(final String tag2, final String message) {
        if (!BuildVars.LOGS_ENABLED) {
            return;
        }
        ensureInitied();
        Log.w(tag2, message);
        if (getInstance().streamWriter != null) {
            getInstance().logQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLog$TkqePyLlP_5oduahnkw4W2pWThg
                @Override // java.lang.Runnable
                public final void run() {
                    FileLog.lambda$w$8(tag2, message);
                }
            });
        }
    }

    static /* synthetic */ void lambda$w$8(String tag2, String message) {
        try {
            getInstance().streamWriter.write(getInstance().dateFormat.format(System.currentTimeMillis()) + " W/" + tag2 + ": " + message + ShellAdbUtils.COMMAND_LINE_END);
            getInstance().streamWriter.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void cleanupLogs() {
        ensureInitied();
        File sdCard = ApplicationLoader.applicationContext.getExternalFilesDir(null);
        if (sdCard == null) {
            return;
        }
        File dir = new File(sdCard.getAbsolutePath() + "/logs");
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if ((getInstance().currentFile == null || !file.getAbsolutePath().equals(getInstance().currentFile.getAbsolutePath())) && (getInstance().networkFile == null || !file.getAbsolutePath().equals(getInstance().networkFile.getAbsolutePath()))) {
                    file.delete();
                }
            }
        }
    }
}
