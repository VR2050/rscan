package com.snail.antifake.jni;

import android.content.Context;
import com.snail.antifake.deviceid.AndroidDeviceIMEIUtil;

/* JADX INFO: loaded from: classes3.dex */
public class EmulatorDetectUtil {

    public interface Arch {
        public static final int ARM32 = 2;
        public static final int ARM64 = 3;
        public static final int X86 = 0;
        public static final int X86_64 = 1;
    }

    public static native boolean detectS();

    static {
        System.loadLibrary("emulator_check");
    }

    public static boolean isEmulator(Context context) {
        return detectS();
    }

    public static boolean isEmulatorFromAll(Context context) {
        return AndroidDeviceIMEIUtil.isRunOnEmulator(context) || detectS();
    }

    public static int getSystemArch() {
        String cpuAbi = PropertiesGet.getString("ro.product.cpu.abi");
        if ("armeabi-v7a".equals(cpuAbi)) {
            return 2;
        }
        if ("arm64-v8a".equals(cpuAbi)) {
            return 3;
        }
        if ("x86".equals(cpuAbi)) {
            return 0;
        }
        return "x86_64".equals(cpuAbi) ? 1 : 3;
    }
}
