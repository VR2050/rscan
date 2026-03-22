package com.shuyu.gsyvideoplayer.utils;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.telephony.TelephonyManager;

/* loaded from: classes2.dex */
public class NetworkUtils {
    public static final int NETWORK_2G = 2;
    public static final int NETWORK_3G = 3;
    public static final int NETWORK_4G = 4;
    public static final int NETWORK_NO = -1;
    private static final int NETWORK_TYPE_GSM = 16;
    private static final int NETWORK_TYPE_IWLAN = 18;
    private static final int NETWORK_TYPE_TD_SCDMA = 17;
    public static final int NETWORK_UNKNOWN = 5;
    public static final int NETWORK_WIFI = 1;

    private NetworkUtils() {
    }

    private static NetworkInfo getActiveNetworkInfo(Context context) {
        return ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0044 A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int getNetWorkType(android.content.Context r3) {
        /*
            android.net.NetworkInfo r3 = getActiveNetworkInfo(r3)
            r0 = 5
            r1 = 1
            if (r3 == 0) goto L49
            boolean r2 = r3.isAvailable()
            if (r2 == 0) goto L49
            int r2 = r3.getType()
            if (r2 != r1) goto L16
            r0 = 1
            goto L4a
        L16:
            int r1 = r3.getType()
            if (r1 != 0) goto L4a
            int r1 = r3.getSubtype()
            r2 = 3
            switch(r1) {
                case 1: goto L46;
                case 2: goto L46;
                case 3: goto L44;
                case 4: goto L46;
                case 5: goto L44;
                case 6: goto L44;
                case 7: goto L46;
                case 8: goto L44;
                case 9: goto L44;
                case 10: goto L44;
                case 11: goto L46;
                case 12: goto L44;
                case 13: goto L41;
                case 14: goto L44;
                case 15: goto L44;
                case 16: goto L46;
                case 17: goto L44;
                case 18: goto L41;
                default: goto L24;
            }
        L24:
            java.lang.String r3 = r3.getSubtypeName()
            java.lang.String r1 = "TD-SCDMA"
            boolean r1 = r3.equalsIgnoreCase(r1)
            if (r1 != 0) goto L44
            java.lang.String r1 = "WCDMA"
            boolean r1 = r3.equalsIgnoreCase(r1)
            if (r1 != 0) goto L44
            java.lang.String r1 = "CDMA2000"
            boolean r3 = r3.equalsIgnoreCase(r1)
            if (r3 == 0) goto L4a
            goto L44
        L41:
            r3 = 4
            r0 = 4
            goto L4a
        L44:
            r0 = 3
            goto L4a
        L46:
            r3 = 2
            r0 = 2
            goto L4a
        L49:
            r0 = -1
        L4a:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.shuyu.gsyvideoplayer.utils.NetworkUtils.getNetWorkType(android.content.Context):int");
    }

    public static String getNetWorkTypeName(Context context) {
        int netWorkType = getNetWorkType(context);
        return netWorkType != -1 ? netWorkType != 1 ? netWorkType != 2 ? netWorkType != 3 ? netWorkType != 4 ? "NETWORK_UNKNOWN" : "NETWORK_4G" : "NETWORK_3G" : "NETWORK_2G" : "NETWORK_WIFI" : "NETWORK_NO";
    }

    public static String getNetworkOperatorName(Context context) {
        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
        if (telephonyManager != null) {
            return telephonyManager.getNetworkOperatorName();
        }
        return null;
    }

    public static int getPhoneType(Context context) {
        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
        if (telephonyManager != null) {
            return telephonyManager.getPhoneType();
        }
        return -1;
    }

    public static boolean is4G(Context context) {
        NetworkInfo activeNetworkInfo = getActiveNetworkInfo(context);
        return activeNetworkInfo != null && activeNetworkInfo.isAvailable() && activeNetworkInfo.getSubtype() == 13;
    }

    public static boolean isAvailable(Context context) {
        NetworkInfo activeNetworkInfo = getActiveNetworkInfo(context);
        return activeNetworkInfo != null && activeNetworkInfo.isAvailable();
    }

    public static boolean isConnected(Context context) {
        NetworkInfo activeNetworkInfo = getActiveNetworkInfo(context);
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public static boolean isWifiConnected(Context context) {
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
        return connectivityManager != null && connectivityManager.getActiveNetworkInfo().getType() == 1;
    }

    public static void openWirelessSettings(Context context) {
        context.startActivity(new Intent("android.settings.SETTINGS"));
    }
}
