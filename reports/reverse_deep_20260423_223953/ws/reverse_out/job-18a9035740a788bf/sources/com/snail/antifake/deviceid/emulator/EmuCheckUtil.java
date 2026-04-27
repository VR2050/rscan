package com.snail.antifake.deviceid.emulator;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.RemoteException;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import androidx.core.content.PermissionChecker;
import com.snail.antifake.IEmulatorCheck;
import com.snail.antifake.deviceid.AndroidDeviceIMEIUtil;
import com.snail.antifake.deviceid.ShellAdbUtils;
import com.snail.antifake.deviceid.deviceid.IPhoneSubInfoUtil;
import com.snail.antifake.deviceid.deviceid.ITelephonyUtil;
import com.snail.antifake.jni.EmulatorCheckService;
import com.snail.antifake.jni.PropertiesGet;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

/* JADX INFO: loaded from: classes3.dex */
public class EmuCheckUtil {

    public interface CheckEmulatorCallBack {
        void onCheckFaild();

        void onCheckSuccess(boolean z);
    }

    public static boolean mayOnEmulator(Context context) {
        return mayOnEmulatorViaQEMU(context) || isEmulatorViaBuild(context) || isEmulatorFromAbi() || isEmulatorFromCpu();
    }

    public static boolean checkPermissionGranted(Context context, String permission) {
        boolean result = true;
        if (Build.VERSION.SDK_INT >= 23) {
            try {
                PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
                int targetSdkVersion = info.applicationInfo.targetSdkVersion;
                if (targetSdkVersion >= 23) {
                    result = context.checkSelfPermission(permission) == 0;
                } else {
                    result = PermissionChecker.checkSelfPermission(context, permission) == 0;
                }
            } catch (Exception e) {
            }
        }
        return result;
    }

    public static boolean isEmulatorViaBuild(Context context) {
        if (!TextUtils.isEmpty(PropertiesGet.getString("ro.product.model")) && PropertiesGet.getString("ro.product.model").toLowerCase().contains("sdk")) {
            return true;
        }
        if (TextUtils.isEmpty(PropertiesGet.getString("ro.product.manufacturer")) || !PropertiesGet.getString("ro.product.manufacture").toLowerCase().contains("unknown")) {
            return !TextUtils.isEmpty(PropertiesGet.getString("ro.product.device")) && PropertiesGet.getString("ro.product.device").toLowerCase().contains("generic");
        }
        return true;
    }

    public static boolean mayOnEmulatorViaQEMU(Context context) {
        String qemu = PropertiesGet.getString("ro.kernel.qemu");
        return "1".equals(qemu);
    }

    public static boolean isFakeEmulatorFromIMEI(Context context) throws RemoteException {
        String deviceId = null;
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService("phone");
            deviceId = tm.getDeviceId();
        } catch (Exception e) {
        }
        String deviceId1 = IPhoneSubInfoUtil.getDeviceId(context);
        String deviceId2 = ITelephonyUtil.getDeviceId(context);
        return !TextUtils.isEmpty(deviceId) && TextUtils.isEmpty(deviceId1) && TextUtils.isEmpty(deviceId2);
    }

    public static boolean hasQemuSocket() {
        File qemuSocket = new File("/dev/socket/qemud");
        return qemuSocket.exists();
    }

    public static boolean hasQemuPipe() {
        File qemuPipe = new File("/dev/socket/qemud");
        return qemuPipe.exists();
    }

    public static String getEmulatorQEMUKernel() {
        return PropertiesGet.getString("ro.kernel.qemu");
    }

    private static boolean isEmulatorFromCpu() {
        ShellAdbUtils.CommandResult commandResult = ShellAdbUtils.execCommand("cat /proc/cpuinfo", false);
        String cpuInfo = commandResult == null ? "" : commandResult.successMsg;
        if (TextUtils.isEmpty(cpuInfo)) {
            return false;
        }
        return cpuInfo.toLowerCase().contains("intel") || cpuInfo.toLowerCase().contains("amd");
    }

    private static boolean isEmulatorFromAbi() {
        String abi = AndroidDeviceIMEIUtil.getCpuAbi();
        return !TextUtils.isEmpty(abi) && abi.contains("x86");
    }

    public static String getCpuInfo() {
        ShellAdbUtils.CommandResult commandResult = ShellAdbUtils.execCommand("cat /proc/cpuinfo", false);
        return commandResult == null ? "" : commandResult.successMsg;
    }

    public static String getQEmuDriverFileString() {
        File driver_file = new File("/proc/tty/drivers");
        StringBuilder stringBuilder = new StringBuilder();
        if (driver_file.exists() && driver_file.canRead()) {
            try {
                char[] data = new char[1024];
                InputStream inStream = new FileInputStream(driver_file);
                Reader in = new InputStreamReader(inStream, "UTF-8");
                while (true) {
                    int rsz = in.read(data, 0, data.length);
                    if (rsz < 0) {
                        break;
                    }
                    stringBuilder.append(data, 0, rsz);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return stringBuilder.toString();
        }
        return "";
    }

    public static void checkEmulatorFromCache(final Context context, final CheckEmulatorCallBack callBack) {
        Intent intent = new Intent(context, (Class<?>) EmulatorCheckService.class);
        context.bindService(intent, new ServiceConnection() { // from class: com.snail.antifake.deviceid.emulator.EmuCheckUtil.1
            @Override // android.content.ServiceConnection
            public void onServiceConnected(ComponentName name, IBinder service) {
                IEmulatorCheck IEmulatorCheck = IEmulatorCheck.Stub.asInterface(service);
                if (IEmulatorCheck != null) {
                    try {
                        callBack.onCheckSuccess(IEmulatorCheck.isEmulator());
                        context.unbindService(this);
                    } catch (RemoteException e) {
                        callBack.onCheckFaild();
                        context.unbindService(this);
                    }
                }
            }

            @Override // android.content.ServiceConnection
            public void onServiceDisconnected(ComponentName name) {
            }
        }, 1);
    }
}
