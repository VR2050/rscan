package com.socks.library.klog;

import android.util.Log;
import com.google.android.gms.wearable.WearableStatusCodes;

/* JADX INFO: loaded from: classes3.dex */
public class BaseLog {
    public static void printDefault(int type, String tag, String msg) {
        int index = 0;
        int countOfSub = msg.length() / WearableStatusCodes.TARGET_NODE_NOT_CONNECTED;
        if (countOfSub > 0) {
            for (int i = 0; i < countOfSub; i++) {
                String sub = msg.substring(index, index + WearableStatusCodes.TARGET_NODE_NOT_CONNECTED);
                printSub(type, tag, sub);
                index += WearableStatusCodes.TARGET_NODE_NOT_CONNECTED;
            }
            int i2 = msg.length();
            printSub(type, tag, msg.substring(index, i2));
            return;
        }
        printSub(type, tag, msg);
    }

    private static void printSub(int type, String tag, String sub) {
        switch (type) {
            case 1:
                Log.v(tag, sub);
                break;
            case 2:
                Log.d(tag, sub);
                break;
            case 3:
                Log.i(tag, sub);
                break;
            case 4:
                Log.w(tag, sub);
                break;
            case 5:
                Log.e(tag, sub);
                break;
            case 6:
                Log.wtf(tag, sub);
                break;
        }
    }
}
