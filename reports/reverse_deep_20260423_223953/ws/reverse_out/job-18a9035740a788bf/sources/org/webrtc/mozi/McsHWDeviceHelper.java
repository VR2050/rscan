package org.webrtc.mozi;

import android.media.MediaCrypto;
import android.media.MediaFormat;
import android.view.Surface;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class McsHWDeviceHelper {
    private static McsHWDeviceHelper instance = null;
    private boolean alignHardwareDecoderResolution;
    private CodecDelegate codecDelegate;
    private MediaFormatHandler decoderMediaFormatHandler;
    private MediaFormatHandler encoderMediaFormatHandler;
    private boolean forceHardwareDecoder;
    private boolean forceHardwareEncoder;
    private boolean isRooms;
    private final String TAG = "McsHWDeviceHelper";
    private boolean supportHardwareDecoder = false;
    private boolean lowLatencyDecode = false;
    private boolean closeSoftware3A = false;
    private boolean encoderSupportCPUOveruse = true;
    private boolean encoderSupportHighlineProfile = false;
    private boolean encoderIsBaseBrAdjuster = false;
    private boolean decoderUseSystemTS = false;
    private boolean decPictureOrderF2 = false;
    private HWDecoderFallbackController hwDecoderFallbackController = null;
    private boolean disableMCAdaptivePlayback = false;
    private int sampleRate = 48000;
    private int minPixelsHardwareDecode = 60000;
    private int fdLimit = 4096;
    private int maxEncoderQSize = 8;
    private int encoderHighUsageThresholdPercent = 400;
    private int keyFrameInterval = -1;
    private final McsHWDeviceConfig hwDeviceConfig = new McsHWDeviceConfig();

    public interface CodecDelegate {
        MediaCrypto crypto(MediaCrypto mediaCrypto);

        int flag(int i);

        MediaFormat mediaFormat(MediaFormat mediaFormat);

        Surface surface(Surface surface);
    }

    public interface HWDecoderFallbackController {
        boolean isFallback(int i, int i2);
    }

    public interface MediaFormatHandler {
        void onHandle(MediaFormat mediaFormat, int i);
    }

    public class MediaFormatMode {
        public static final int K_REALTIMEVIDEO = 0;
        public static final int K_SCREENSHARING = 1;
        public static final int k_UNKNOWN = -1;

        public MediaFormatMode() {
        }
    }

    public static McsHWDeviceHelper getInstance() {
        if (instance == null) {
            instance = new McsHWDeviceHelper();
        }
        return instance;
    }

    public McsHWDeviceHelper() {
        this.isRooms = false;
        this.forceHardwareEncoder = false;
        this.forceHardwareDecoder = false;
        this.forceHardwareEncoder = false;
        this.forceHardwareDecoder = false;
        this.isRooms = false;
    }

    public void setMcsHardwareConfig(boolean forceHardwareEncoder, boolean forceHardwareDecoder, boolean isRooms) {
        this.forceHardwareEncoder = forceHardwareEncoder;
        this.forceHardwareDecoder = forceHardwareDecoder;
        this.isRooms = isRooms;
    }

    public boolean closeAudioSW3A() {
        return this.closeSoftware3A;
    }

    public void setCloseAudioSW3A(boolean close) {
        this.closeSoftware3A = close;
    }

    public int audioSampleRate() {
        return this.sampleRate;
    }

    public void setAudioSampleRate(int sampleRate) {
        this.sampleRate = sampleRate;
    }

    private static void jsonPut(JSONObject json, String key, Object value) {
        try {
            json.put(key, value);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }

    private String updateHWJson() {
        JSONObject json = new JSONObject();
        JSONObject base = new JSONObject();
        jsonPut(base, "isRooms", Boolean.valueOf(this.isRooms));
        jsonPut(base, "fdLimit", Integer.valueOf(this.fdLimit));
        jsonPut(json, "baseConfig", base);
        JSONObject videoEncoder = new JSONObject();
        jsonPut(videoEncoder, "supportHW", true);
        jsonPut(videoEncoder, "maxEncoderQSize", Integer.valueOf(this.maxEncoderQSize));
        jsonPut(videoEncoder, "highUsageThresholdPercent", Integer.valueOf(this.encoderHighUsageThresholdPercent));
        jsonPut(videoEncoder, "supportCPUOveruse", Boolean.valueOf(this.encoderSupportCPUOveruse));
        jsonPut(json, "videoEncoderConfig", videoEncoder);
        JSONObject videoDecoder = new JSONObject();
        jsonPut(videoDecoder, "supportHW", true);
        jsonPut(videoDecoder, "minPixelsHW", Integer.valueOf(this.minPixelsHardwareDecode));
        jsonPut(videoDecoder, "decoderUseSystemTS", Boolean.valueOf(this.decoderUseSystemTS));
        jsonPut(json, "videoDecoderConfig", videoDecoder);
        JSONObject audioProcess = new JSONObject();
        jsonPut(audioProcess, "closeSoftware3A", Boolean.valueOf(this.closeSoftware3A));
        jsonPut(json, "audioProcessConfig", audioProcess);
        return json.toString();
    }

    public void updateHWDeviceConfig() {
        String config = updateHWJson();
        Logging.d("McsHWDeviceHelper", "rooms hw device config:" + config);
        this.hwDeviceConfig.updateConfig(config);
    }

    public boolean isRooms() {
        return this.isRooms;
    }

    public void setIsRooms(boolean rooms) {
        this.isRooms = rooms;
    }

    public boolean forceHardwareEncoder() {
        return this.forceHardwareEncoder;
    }

    public void setForceHardwareEncoder(boolean force) {
        this.forceHardwareEncoder = force;
    }

    public boolean forceHardwareDecoder() {
        return this.forceHardwareDecoder;
    }

    public void setForceHardwareDecoder(boolean force) {
        this.forceHardwareDecoder = force;
    }

    public boolean supportHardwareDecoder() {
        return this.supportHardwareDecoder;
    }

    public void setSupportHardwareDecoder(boolean hw) {
        this.supportHardwareDecoder = hw;
    }

    public int minPixelsHardwareDecode() {
        return this.minPixelsHardwareDecode;
    }

    public void setMinPixelsHardwareDecode(int pixels) {
        this.minPixelsHardwareDecode = pixels;
    }

    public boolean decoderUseSystemTS() {
        return this.decoderUseSystemTS;
    }

    public void setDecoderUseSystemTS(boolean decoderUseSystemTS) {
        this.decoderUseSystemTS = decoderUseSystemTS;
    }

    public boolean lowLatencyDecode() {
        return this.lowLatencyDecode;
    }

    public void setLowLatencyDecode(boolean ll) {
        this.lowLatencyDecode = ll;
    }

    public boolean decPictureOrderF2() {
        return this.decPictureOrderF2;
    }

    public void setDecPictureOrderF2(boolean ll) {
        this.decPictureOrderF2 = ll;
    }

    public void setEncoderKeyFrameInterval(int val) {
        this.keyFrameInterval = val;
    }

    public int getEncoderKeyFrameInterval() {
        return this.keyFrameInterval;
    }

    public boolean encoderSupportCPUOveruse() {
        return this.encoderSupportCPUOveruse;
    }

    public void setEncoderSupportCPUOveruse(boolean support) {
        this.encoderSupportCPUOveruse = support;
    }

    public boolean encoderSupportHighlineProfile() {
        return this.encoderSupportHighlineProfile;
    }

    public void setEncoderSupportHighlineProfile(boolean support) {
        this.encoderSupportHighlineProfile = support;
    }

    public boolean encoderIsBaseBrAdjuster() {
        return this.encoderIsBaseBrAdjuster;
    }

    public void setEncoderIsBaseBrAdjuster(boolean isBaseBrA) {
        this.encoderIsBaseBrAdjuster = isBaseBrA;
    }

    public MediaFormatHandler getDecoderMediaFormatHandler() {
        return this.decoderMediaFormatHandler;
    }

    public void setDecoderMediaFormatHandler(MediaFormatHandler handler) {
        this.decoderMediaFormatHandler = handler;
    }

    public MediaFormatHandler getEncoderMediaFormatHandler() {
        return this.encoderMediaFormatHandler;
    }

    public void setEncoderMediaFormatHandler(MediaFormatHandler handler) {
        this.encoderMediaFormatHandler = handler;
    }

    public CodecDelegate getCodecDelegate() {
        return this.codecDelegate;
    }

    public void setCodecDelegate(CodecDelegate delegate) {
        this.codecDelegate = delegate;
    }

    public void setHwDecoderFallbackController(HWDecoderFallbackController hwDecoderFallbackController) {
        this.hwDecoderFallbackController = hwDecoderFallbackController;
    }

    public HWDecoderFallbackController getHwDecoderFallbackController() {
        return this.hwDecoderFallbackController;
    }

    public boolean isAlignHardwareDecoderResolution() {
        return this.alignHardwareDecoderResolution;
    }

    public void setAlignHardwareDecoderResolution(boolean alignHardwareDecoderResolution) {
        this.alignHardwareDecoderResolution = alignHardwareDecoderResolution;
    }

    public boolean isDisableMCAdaptivePlayback() {
        return this.disableMCAdaptivePlayback;
    }

    public void setDisableMCAdaptivePlayback(boolean disable) {
        this.disableMCAdaptivePlayback = disable;
    }
}
