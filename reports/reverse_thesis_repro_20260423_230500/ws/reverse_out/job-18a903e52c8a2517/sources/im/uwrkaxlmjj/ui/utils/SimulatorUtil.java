package im.uwrkaxlmjj.ui.utils;

import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.net.Uri;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.text.TextUtils;

/* JADX INFO: loaded from: classes5.dex */
public class SimulatorUtil {
    public static boolean isSimulator(Context context) {
        Intent intent = new Intent();
        intent.setData(Uri.parse("tel:123456"));
        intent.setAction("android.intent.action.DIAL");
        boolean canCallPhone = intent.resolveActivity(context.getPackageManager()) != null;
        boolean isSimulator = Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.toLowerCase().contains("vbox") || Build.FINGERPRINT.toLowerCase().contains("test-keys") || Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator") || Build.MODEL.contains("MuMu") || Build.MODEL.contains("virtual") || Build.SERIAL.equalsIgnoreCase("android") || Build.MANUFACTURER.contains("Genymotion") || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) || "google_sdk".equals(Build.PRODUCT) || ((TelephonyManager) context.getSystemService("phone")).getNetworkOperatorName().toLowerCase().equals("android") || !canCallPhone;
        if (!isSimulator && !hasLightSensor(context).booleanValue()) {
            return true;
        }
        if (isSimulator && canCallPhone && Build.BRAND.equalsIgnoreCase("HUAWEI") && hasLightSensor(context).booleanValue()) {
            return false;
        }
        return isSimulator;
    }

    public boolean notHasBlueTooth() {
        BluetoothAdapter ba = BluetoothAdapter.getDefaultAdapter();
        if (ba == null) {
            return true;
        }
        String name = ba.getName();
        if (TextUtils.isEmpty(name)) {
            return true;
        }
        return false;
    }

    public static Boolean hasLightSensor(Context context) {
        SensorManager sensorManager = (SensorManager) context.getSystemService("sensor");
        Sensor sensor8 = sensorManager.getDefaultSensor(5);
        if (sensor8 == null) {
            return false;
        }
        return true;
    }
}
