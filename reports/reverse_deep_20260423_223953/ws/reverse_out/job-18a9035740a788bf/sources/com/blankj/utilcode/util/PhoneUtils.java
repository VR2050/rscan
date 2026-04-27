package com.blankj.utilcode.util;

import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import com.google.android.exoplayer2.C;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes.dex */
public final class PhoneUtils {
    private PhoneUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static boolean isPhone() {
        TelephonyManager tm = getTelephonyManager();
        return tm.getPhoneType() != 0;
    }

    public static String getDeviceId() {
        if (Build.VERSION.SDK_INT >= 29) {
            return "";
        }
        TelephonyManager tm = getTelephonyManager();
        String deviceId = tm.getDeviceId();
        if (!TextUtils.isEmpty(deviceId)) {
            return deviceId;
        }
        if (Build.VERSION.SDK_INT < 26) {
            return "";
        }
        String imei = tm.getImei();
        if (!TextUtils.isEmpty(imei)) {
            return imei;
        }
        String meid = tm.getMeid();
        return TextUtils.isEmpty(meid) ? "" : meid;
    }

    public static String getSerial() {
        return Build.VERSION.SDK_INT >= 26 ? Build.getSerial() : Build.SERIAL;
    }

    public static String getIMEI() {
        return getImeiOrMeid(true);
    }

    public static String getMEID() {
        return getImeiOrMeid(false);
    }

    public static String getImeiOrMeid(boolean isImei) {
        if (Build.VERSION.SDK_INT >= 29) {
            return "";
        }
        TelephonyManager tm = getTelephonyManager();
        int i = 1;
        if (Build.VERSION.SDK_INT >= 26) {
            if (isImei) {
                return getMinOne(tm.getImei(0), tm.getImei(1));
            }
            return getMinOne(tm.getMeid(0), tm.getMeid(1));
        }
        if (Build.VERSION.SDK_INT >= 21) {
            String ids = getSystemPropertyByReflect(isImei ? "ril.gsm.imei" : "ril.cdma.meid");
            if (!TextUtils.isEmpty(ids)) {
                String[] idArr = ids.split(",");
                if (idArr.length == 2) {
                    return getMinOne(idArr[0], idArr[1]);
                }
                return idArr[0];
            }
            String id0 = tm.getDeviceId();
            String id1 = "";
            try {
                Method method = tm.getClass().getMethod("getDeviceId", Integer.TYPE);
                Object[] objArr = new Object[1];
                if (!isImei) {
                    i = 2;
                }
                objArr[0] = Integer.valueOf(i);
                id1 = (String) method.invoke(tm, objArr);
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (NoSuchMethodException e2) {
                e2.printStackTrace();
            } catch (InvocationTargetException e3) {
                e3.printStackTrace();
            }
            if (isImei) {
                if (id0 != null && id0.length() < 15) {
                    id0 = "";
                }
                if (id1 != null && id1.length() < 15) {
                    id1 = "";
                }
            } else {
                if (id0 != null && id0.length() == 14) {
                    id0 = "";
                }
                if (id1 != null && id1.length() == 14) {
                    id1 = "";
                }
            }
            return getMinOne(id0, id1);
        }
        String deviceId = tm.getDeviceId();
        if (isImei) {
            if (deviceId != null && deviceId.length() >= 15) {
                return deviceId;
            }
        } else if (deviceId != null && deviceId.length() == 14) {
            return deviceId;
        }
        return "";
    }

    private static String getMinOne(String s0, String s1) {
        boolean empty0 = TextUtils.isEmpty(s0);
        boolean empty1 = TextUtils.isEmpty(s1);
        if (empty0 && empty1) {
            return "";
        }
        if (empty0 || empty1) {
            return !empty0 ? s0 : s1;
        }
        if (s0.compareTo(s1) <= 0) {
            return s0;
        }
        return s1;
    }

    private static String getSystemPropertyByReflect(String key) {
        try {
            Class<?> clz = Class.forName("android.os.SystemProperties");
            Method getMethod = clz.getMethod("get", String.class, String.class);
            return (String) getMethod.invoke(clz, key, "");
        } catch (Exception e) {
            return "";
        }
    }

    public static String getIMSI() {
        return getTelephonyManager().getSubscriberId();
    }

    public static int getPhoneType() {
        TelephonyManager tm = getTelephonyManager();
        return tm.getPhoneType();
    }

    public static boolean isSimCardReady() {
        TelephonyManager tm = getTelephonyManager();
        return tm.getSimState() == 5;
    }

    public static String getSimOperatorName() {
        TelephonyManager tm = getTelephonyManager();
        return tm.getSimOperatorName();
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static String getSimOperatorByMnc() {
        TelephonyManager tm = getTelephonyManager();
        String operator = tm.getSimOperator();
        if (operator == null) {
            return "";
        }
        byte b = -1;
        int iHashCode = operator.hashCode();
        if (iHashCode != 49679479) {
            if (iHashCode != 49679502) {
                if (iHashCode != 49679532) {
                    switch (iHashCode) {
                        case 49679470:
                            if (operator.equals("46000")) {
                                b = 0;
                            }
                            break;
                        case 49679471:
                            if (operator.equals("46001")) {
                                b = 4;
                            }
                            break;
                        case 49679472:
                            if (operator.equals("46002")) {
                                b = 1;
                            }
                            break;
                        case 49679473:
                            if (operator.equals("46003")) {
                                b = 7;
                            }
                            break;
                        default:
                            switch (iHashCode) {
                                case 49679475:
                                    if (operator.equals("46005")) {
                                        b = 8;
                                    }
                                    break;
                                case 49679476:
                                    if (operator.equals("46006")) {
                                        b = 5;
                                    }
                                    break;
                                case 49679477:
                                    if (operator.equals("46007")) {
                                        b = 2;
                                    }
                                    break;
                            }
                            break;
                    }
                } else if (operator.equals("46020")) {
                    b = 3;
                }
            } else if (operator.equals("46011")) {
                b = 9;
            }
        } else if (operator.equals("46009")) {
            b = 6;
        }
        switch (b) {
            case 0:
            case 1:
            case 2:
            case 3:
                return "中国移动";
            case 4:
            case 5:
            case 6:
                return "中国联通";
            case 7:
            case 8:
            case 9:
                return "中国电信";
            default:
                return operator;
        }
    }

    public static boolean dial(String phoneNumber) {
        Intent intent = new Intent("android.intent.action.DIAL", Uri.parse("tel:" + phoneNumber));
        if (isIntentAvailable(intent)) {
            Utils.getApp().startActivity(intent.addFlags(C.ENCODING_PCM_MU_LAW));
            return true;
        }
        return false;
    }

    public static boolean call(String phoneNumber) {
        Intent intent = new Intent("android.intent.action.CALL", Uri.parse("tel:" + phoneNumber));
        if (isIntentAvailable(intent)) {
            Utils.getApp().startActivity(intent.addFlags(C.ENCODING_PCM_MU_LAW));
            return true;
        }
        return false;
    }

    public static boolean sendSms(String phoneNumber, String content) {
        Uri uri = Uri.parse("smsto:" + phoneNumber);
        Intent intent = new Intent("android.intent.action.SENDTO", uri);
        if (isIntentAvailable(intent)) {
            intent.putExtra("sms_body", content);
            Utils.getApp().startActivity(intent.addFlags(C.ENCODING_PCM_MU_LAW));
            return true;
        }
        return false;
    }

    private static TelephonyManager getTelephonyManager() {
        return (TelephonyManager) Utils.getApp().getSystemService("phone");
    }

    private static boolean isIntentAvailable(Intent intent) {
        return Utils.getApp().getPackageManager().queryIntentActivities(intent, 65536).size() > 0;
    }
}
