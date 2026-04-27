package com.snail.antifake.deviceid.deviceid;

import android.content.Context;
import android.os.RemoteException;
import android.telephony.TelephonyManager;
import android.text.TextUtils;

/* JADX INFO: loaded from: classes3.dex */
public class DeviceIdUtil {
    public static String getDeviceId(Context context) throws RemoteException {
        String deviceIdLevel2 = ITelephonyUtil.getDeviceIdLevel2(context);
        String deviceId = deviceIdLevel2;
        if (TextUtils.isEmpty(deviceIdLevel2)) {
            String deviceIdLevel22 = IPhoneSubInfoUtil.getDeviceIdLevel2(context);
            deviceId = deviceIdLevel22;
            if (TextUtils.isEmpty(deviceIdLevel22)) {
                String deviceIdLevel1 = ITelephonyUtil.getDeviceIdLevel1(context);
                String deviceId2 = deviceIdLevel1;
                if (TextUtils.isEmpty(deviceIdLevel1)) {
                    String deviceIdLevel12 = IPhoneSubInfoUtil.getDeviceIdLevel1(context);
                    deviceId2 = deviceIdLevel12;
                    if (TextUtils.isEmpty(deviceIdLevel12)) {
                        String deviceIdLevel0 = IPhoneSubInfoUtil.getDeviceIdLevel0(context);
                        String deviceId3 = deviceIdLevel0;
                        if (TextUtils.isEmpty(deviceIdLevel0)) {
                            String deviceIdLevel02 = ITelephonyUtil.getDeviceIdLevel0(context);
                            deviceId3 = deviceIdLevel02;
                            if (TextUtils.isEmpty(deviceIdLevel02)) {
                                try {
                                    TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
                                    String deviceId4 = telephonyManager.getDeviceId();
                                    return deviceId4;
                                } catch (Exception e) {
                                    return deviceId3;
                                }
                            }
                        }
                        return deviceId3;
                    }
                }
                return deviceId2;
            }
        }
        return deviceId;
    }

    public static boolean isEmulatorFromDeviceId(Context context) {
        return isAllZero(getDeviceId(context));
    }

    private static boolean isAllZero(String content) {
        if (TextUtils.isEmpty(content)) {
            return false;
        }
        for (int i = 0; i < content.length(); i++) {
            if (content.charAt(i) != '0') {
                return false;
            }
        }
        return true;
    }
}
