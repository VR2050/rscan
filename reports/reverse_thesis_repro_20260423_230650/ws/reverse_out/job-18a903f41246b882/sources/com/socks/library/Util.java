package com.socks.library;

import android.text.TextUtils;
import android.util.Log;
import com.snail.antifake.deviceid.ShellAdbUtils;

/* JADX INFO: loaded from: classes3.dex */
public class Util {
    public static boolean isEmpty(String line) {
        return TextUtils.isEmpty(line) || line.equals(ShellAdbUtils.COMMAND_LINE_END) || line.equals("\t") || TextUtils.isEmpty(line.trim());
    }

    public static void printLine(String tag, boolean isTop) {
        if (isTop) {
            Log.d(tag, "╔═══════════════════════════════════════════════════════════════════════════════════════");
        } else {
            Log.d(tag, "╚═══════════════════════════════════════════════════════════════════════════════════════");
        }
    }
}
