package com.just.agentweb;

import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import android.webkit.WebView;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.util.HashSet;
import java.util.Set;

/* JADX INFO: loaded from: classes3.dex */
public class AgentWebCompat {
    public static void setDataDirectorySuffix(Context context) {
        if (Build.VERSION.SDK_INT < 28) {
            return;
        }
        try {
            Set<String> pathSet = new HashSet<>();
            String dataPath = context.getDataDir().getAbsolutePath();
            String processName = ProcessUtils.getCurrentProcessName(context);
            if (!TextUtils.equals(context.getPackageName(), processName)) {
                String suffix = TextUtils.isEmpty(processName) ? context.getPackageName() : processName;
                WebView.setDataDirectorySuffix(suffix);
                String suffix2 = "_" + suffix;
                pathSet.add(dataPath + "/app_webview" + suffix2 + "/webview_data.lock");
                if (RomUtils.isHuawei()) {
                    pathSet.add(dataPath + "/app_hws_webview" + suffix2 + "/webview_data.lock");
                }
            } else {
                String suffix3 = "_" + processName;
                pathSet.add(dataPath + "/app_webview/webview_data.lock");
                pathSet.add(dataPath + "/app_webview" + suffix3 + "/webview_data.lock");
                if (RomUtils.isHuawei()) {
                    pathSet.add(dataPath + "/app_hws_webview/webview_data.lock");
                    pathSet.add(dataPath + "/app_hws_webview" + suffix3 + "/webview_data.lock");
                }
            }
            for (String path : pathSet) {
                File file = new File(path);
                if (file.exists()) {
                    tryLockOrRecreateFile(file);
                    return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void tryLockOrRecreateFile(File file) {
        try {
            FileLock tryLock = new RandomAccessFile(file, "rw").getChannel().tryLock();
            if (tryLock != null) {
                tryLock.close();
            } else {
                createFile(file, file.delete());
            }
        } catch (Exception e) {
            e.printStackTrace();
            boolean deleted = false;
            if (file.exists()) {
                deleted = file.delete();
            }
            createFile(file, deleted);
        }
    }

    private static void createFile(File file, boolean deleted) {
        if (deleted) {
            try {
                if (!file.exists()) {
                    file.createNewFile();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
