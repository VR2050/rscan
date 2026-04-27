package org.webrtc.mozi;

import android.os.Build;
import com.king.zxing.util.LogUtils;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class McsConfig {
    public static final int B_FRAME_FALLBACK_2_BASELINE = 1;
    public static final int B_FRAME_FALLBACK_2_SOFTWARE = 2;
    private final String TAG;
    private JSONObject configs;
    private final long nativePtr;
    private static ArrayList<String> list_cpus4framerate_adjuster = new ArrayList<>();
    private static ArrayList<String> list_cpus4base_adjuster = new ArrayList<>();
    private static boolean allowUnexpectedBFrameInHWEnc = false;
    private static int bFrameFallbackAction = 1;
    private static boolean newCamera1CaptureFpsLogic = false;

    private native void nativeDisableLibyuvNeon(long j, boolean z);

    private native void nativeUpdateAndroidHwDeviceConfig(long j, String str);

    private native void nativeUpdateAudioDeviceConfig(long j, String str);

    private native void nativeUpdateClientAudioConfig(long j, String str);

    private native void nativeUpdateConfig(long j, String str);

    private native void nativeUpdateGraySwitchConfig(long j, String str);

    private native void nativeUpdateGraySwitchKey(long j, String str, boolean z);

    private native void nativeUpdatePreloadConfig(long j, String str);

    private native void nativeUpdateProxyInfo(long j, ProxyInfo proxyInfo);

    private native void nativeUpdateTurnAuthConfig(long j, String str);

    @Deprecated
    private McsConfig() {
        this.TAG = "McsConfig";
        this.nativePtr = 0L;
    }

    public McsConfig(long nativePtr) {
        this.TAG = "McsConfig";
        this.nativePtr = nativePtr;
    }

    public void updateConfig(String config) {
        nativeUpdateConfig(this.nativePtr, config);
        list_cpus4framerate_adjuster.add("mt6750");
        list_cpus4base_adjuster.add("exynos9820");
        list_cpus4base_adjuster.add("erd9630");
        try {
            JSONObject root = new JSONObject(config);
            JSONObject mediacodecConfig = root.getJSONObject("videoMediaCodecConfig");
            try {
                JSONObject bitrateAdjuster = mediacodecConfig.getJSONObject("bitrateAdjuster");
                JSONArray cpus4bitrateadjuster = bitrateAdjuster.getJSONArray("framerateAdjuster");
                for (int i = 0; i < cpus4bitrateadjuster.length(); i++) {
                    Logging.d("McsConfig", "updateConfig, add cpu for framerate adjuster " + cpus4bitrateadjuster.getString(i));
                    list_cpus4framerate_adjuster.add(cpus4bitrateadjuster.getString(i));
                }
                JSONArray cpus4bitrateadjuster2 = bitrateAdjuster.getJSONArray("baseAdjuster");
                for (int i2 = 0; i2 < cpus4bitrateadjuster2.length(); i2++) {
                    Logging.d("McsConfig", "updateConfig, add cpu for base adjuster " + cpus4bitrateadjuster2.getString(i2));
                    list_cpus4base_adjuster.add(cpus4bitrateadjuster2.getString(i2));
                }
            } catch (JSONException e) {
                e.printStackTrace();
            }
            try {
                JSONArray cpus4disableneon = mediacodecConfig.getJSONArray("disableLibyuvNeon");
                int i3 = 0;
                while (true) {
                    if (i3 < cpus4disableneon.length()) {
                        String cpu = cpus4disableneon.getString(i3);
                        Logging.d("McsConfig", "updateConfig, cpu for disable libyuv neon: " + cpu);
                        if (cpu.equals("all")) {
                            nativeDisableLibyuvNeon(this.nativePtr, true);
                            break;
                        } else if (cpu.equals(Build.HARDWARE) || cpu.equals(Build.BOARD)) {
                            break;
                        } else {
                            i3++;
                        }
                    }
                }
                Logging.d("McsConfig", "updateConfig, bingo disable libyuv neon, " + Build.HARDWARE + LogUtils.VERTICAL + Build.BOARD);
                nativeDisableLibyuvNeon(this.nativePtr, true);
            } catch (JSONException e2) {
                e2.printStackTrace();
            }
            try {
                allowUnexpectedBFrameInHWEnc = mediacodecConfig.getBoolean("allowUnexpectedBFrameInHWEnc");
            } catch (JSONException e3) {
                e3.printStackTrace();
            }
            try {
                int bFrameAction = mediacodecConfig.getInt("unexpectedBFrameAction");
                if (bFrameAction == 1 || bFrameAction == 2) {
                    bFrameFallbackAction = bFrameAction;
                }
            } catch (JSONException e4) {
                e4.printStackTrace();
            }
        } catch (JSONException e5) {
            e5.printStackTrace();
        }
        try {
            JSONObject root2 = new JSONObject(config);
            JSONObject cameraVideoConfig = root2.getJSONObject("cameraVideoConfig");
            if (cameraVideoConfig != null) {
                try {
                    newCamera1CaptureFpsLogic = cameraVideoConfig.getBoolean("newCamera1CaptureFpsLogic");
                } catch (JSONException e6) {
                    e6.printStackTrace();
                }
            }
        } catch (JSONException e7) {
            e7.printStackTrace();
        }
    }

    public void updateTurnAuthConfig(String token) {
        nativeUpdateTurnAuthConfig(this.nativePtr, token);
    }

    public void updateClientAudioConfig(String config) {
        nativeUpdateClientAudioConfig(this.nativePtr, config);
    }

    public void updateAudioDeviceConfig(String config) {
        nativeUpdateAudioDeviceConfig(this.nativePtr, config);
    }

    public void updatePreloadConfig(String config) {
        nativeUpdatePreloadConfig(this.nativePtr, config);
    }

    public void UpdateAndroidHwDeviceConfig(String config) {
        nativeUpdateAndroidHwDeviceConfig(this.nativePtr, config);
    }

    public void updateGraySwitchConfig(String config) {
        nativeUpdateGraySwitchConfig(this.nativePtr, config);
    }

    public void updateGraySwitchKey(String key, boolean value) {
        nativeUpdateGraySwitchKey(this.nativePtr, key, value);
    }

    public void updateProxyInfo(ProxyInfo proxy) {
        nativeUpdateProxyInfo(this.nativePtr, proxy);
    }

    public static ArrayList<String> listCpuOfFramerateAdjuster() {
        return list_cpus4framerate_adjuster;
    }

    public static ArrayList<String> listCpuOfBaseAdjuster() {
        return list_cpus4base_adjuster;
    }

    public static boolean allowUnexpectedBFrameInHWEncoder() {
        return allowUnexpectedBFrameInHWEnc;
    }

    public static int getUnexpectedBFrameAction() {
        return bFrameFallbackAction;
    }

    public static boolean newCamera1CaptureFpsLogic() {
        return newCamera1CaptureFpsLogic;
    }
}
