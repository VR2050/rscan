package im.uwrkaxlmjj.utils;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Point;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.view.WindowManager;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.UUID;
import kotlin.UByte;

/* JADX INFO: loaded from: classes5.dex */
public class FingerprintUtil {
    public static String getDeviceId(Context context) {
        StringBuilder sbDeviceId = new StringBuilder();
        String androidid = getAndroidId(context);
        String serial = getSERIAL();
        String uuid = getDeviceUUID().replace("-", "");
        String uuid2 = getDeviceUUID2().replace("-", "");
        if (androidid != null && androidid.length() > 0) {
            sbDeviceId.append(androidid);
            sbDeviceId.append(LogUtils.VERTICAL);
        }
        if (serial != null && serial.length() > 0) {
            sbDeviceId.append(serial);
            sbDeviceId.append(LogUtils.VERTICAL);
        }
        if (uuid != null && uuid.length() > 0) {
            sbDeviceId.append(uuid);
            sbDeviceId.append(LogUtils.VERTICAL);
        }
        if (uuid2 != null && uuid2.length() > 0) {
            sbDeviceId.append(uuid2);
        }
        if (sbDeviceId.length() > 0) {
            try {
                byte[] hash = getHashByString(sbDeviceId.toString());
                String sha1 = bytesToHex(hash);
                if (sha1 != null) {
                    if (sha1.length() > 0) {
                        return sha1;
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        return UUID.randomUUID().toString().replace("-", "");
    }

    private static String getIMEI(Context context) {
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService("phone");
            return tm.getDeviceId();
        } catch (Exception ex) {
            ex.printStackTrace();
            return "";
        }
    }

    private static String getIMEI10(Context context) {
        try {
            TelephonyManager manager = (TelephonyManager) context.getSystemService("phone");
            Method method = manager.getClass().getMethod("getImei", Integer.TYPE);
            return (String) method.invoke(manager, 0);
        } catch (Exception ex) {
            ex.printStackTrace();
            return "";
        }
    }

    private static String getAndroidId(Context context) {
        try {
            return Settings.Secure.getString(context.getContentResolver(), "android_id");
        } catch (Exception ex) {
            ex.printStackTrace();
            return "";
        }
    }

    private static String getSERIAL() {
        try {
            return Build.SERIAL;
        } catch (Exception ex) {
            ex.printStackTrace();
            return "";
        }
    }

    private static String getDeviceUUID() {
        try {
            String dev = "38837561" + (Build.BOARD.length() % 10) + (Build.BRAND.length() % 10) + (Build.DEVICE.length() % 10) + (Build.HARDWARE.length() % 10) + (Build.ID.length() % 10) + (Build.MODEL.length() % 10) + (Build.PRODUCT.length() % 10) + (Build.SERIAL.length() % 10);
            return new UUID(dev.hashCode(), Build.SERIAL.hashCode()).toString();
        } catch (Exception ex) {
            ex.printStackTrace();
            return "";
        }
    }

    public static String getDeviceUUID2() {
        StringBuilder stringBuffer = new StringBuilder();
        String manufacturer = Build.MANUFACTURER;
        stringBuffer.append(manufacturer);
        stringBuffer.append("/");
        stringBuffer.append(Build.BRAND);
        stringBuffer.append("/");
        stringBuffer.append(Build.DEVICE);
        stringBuffer.append("/");
        stringBuffer.append(Build.HARDWARE);
        stringBuffer.append("/");
        stringBuffer.append(Build.MODEL);
        stringBuffer.append("/");
        stringBuffer.append(Build.PRODUCT);
        stringBuffer.append("/");
        stringBuffer.append(Build.TAGS);
        stringBuffer.append("/");
        stringBuffer.append(Build.TYPE);
        stringBuffer.append("/");
        stringBuffer.append(Build.USER);
        stringBuffer.append("/");
        if (Build.VERSION.SDK_INT >= 21) {
            stringBuffer.append(Build.SUPPORTED_ABIS[0]);
            stringBuffer.append("/");
        }
        stringBuffer.append(getResolutions());
        stringBuffer.append("/");
        stringBuffer.append(getScreenDensity());
        stringBuffer.append("/");
        stringBuffer.append(getScreenDensityDpi());
        return stringBuffer.toString();
    }

    public static String getResolutions() {
        Point outSize = new Point();
        WindowManager wm = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
        wm.getDefaultDisplay().getRealSize(outSize);
        int x = outSize.x;
        int y = outSize.y;
        return x + "*" + y;
    }

    public static float getScreenDensity() {
        return Resources.getSystem().getDisplayMetrics().density;
    }

    public static int getScreenDensityDpi() {
        return Resources.getSystem().getDisplayMetrics().densityDpi;
    }

    private static byte[] getHashByString(String data) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
            messageDigest.reset();
            messageDigest.update(data.getBytes("UTF-8"));
            return messageDigest.digest();
        } catch (Exception e) {
            return "".getBytes();
        }
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            String stmp = Integer.toHexString(b & UByte.MAX_VALUE);
            if (stmp.length() == 1) {
                sb.append("0");
            }
            sb.append(stmp);
        }
        return sb.toString().toUpperCase(Locale.CHINA);
    }
}
