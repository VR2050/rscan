package org.webrtc.mozi;

import java.nio.ByteBuffer;
import javax.annotation.Nullable;
import org.webrtc.mozi.EncodedImage;

/* JADX INFO: loaded from: classes3.dex */
public interface VideoEncoder {

    public interface Callback {
        void onEncodeError(int i, int i2);

        void onEncodedFrame(EncodedImage encodedImage, CodecSpecificInfo codecSpecificInfo);

        int onParseFrame(ByteBuffer byteBuffer, int i);

        ByteBuffer onWriteCropInfo(ByteBuffer byteBuffer, int i, int i2, int i3, int i4);
    }

    public static class CodecSpecificInfo {
        public boolean end_mark;
        public int sim_index;
    }

    public static class CodecSpecificInfoH264 extends CodecSpecificInfo {
    }

    public static class CodecSpecificInfoVP8 extends CodecSpecificInfo {
    }

    public static class CodecSpecificInfoVP9 extends CodecSpecificInfo {
    }

    long createNativeVideoEncoder();

    void decideToFallback();

    VideoCodecStatus encode(VideoFrame videoFrame, EncodeInfo encodeInfo);

    String getImplementationName();

    String getImplementationName2();

    String getProfileLevel();

    ScalingSettings getScalingSettings();

    VideoCodecStatus initEncode(Settings settings, Callback callback);

    boolean isHardwareEncoder();

    VideoCodecStatus release();

    int setAdaptedFramerateRatio(int i, int i2, int i3);

    VideoCodecStatus setChannelParameters(short s, long j);

    VideoCodecStatus setRateAllocation(BitrateAllocation bitrateAllocation, int i);

    void turnOffLayer(int i);

    void turnOnLayer(int i);

    VideoCodecStatus updateSimulcastConfig(LayerSetting[] layerSettingArr);

    public static class LayerSetting {
        public boolean active;
        public int height;
        public int maxFramerate;
        public int minFramerate;
        public int targetBitrate;
        public int width;

        public LayerSetting(int width, int height, int targetBitrate, int maxFramerate, int minFramerate, boolean active) {
            this.width = width;
            this.height = height;
            this.targetBitrate = targetBitrate;
            this.maxFramerate = maxFramerate;
            this.minFramerate = minFramerate;
            this.active = active;
        }
    }

    public static class Settings {
        public static final int K_REALTIMEVIDEO = 0;
        public static final int K_SCREENSHARING = 1;
        public final boolean automaticResizeOn;
        public LayerSetting[] layers;
        public final int mode;
        public final int numberOfCores;

        public Settings(int numberOfCores, LayerSetting[] layers, boolean automaticResizeOn, int mode) {
            this.numberOfCores = numberOfCores;
            this.layers = layers;
            this.automaticResizeOn = automaticResizeOn;
            this.mode = mode;
        }
    }

    public static class EncodeInfo {
        public final EncodedImage.FrameType[] frameTypes;

        public EncodeInfo(EncodedImage.FrameType[] frameTypes) {
            this.frameTypes = frameTypes;
        }
    }

    public static class BitrateAllocation {
        public final int[][] bitratesBbs;

        public BitrateAllocation(int[][] bitratesBbs) {
            this.bitratesBbs = bitratesBbs;
        }

        public int getSum() {
            int sum = 0;
            for (int[] spatialLayer : this.bitratesBbs) {
                for (int bitrate : spatialLayer) {
                    sum += bitrate;
                }
            }
            return sum;
        }

        public int getLayerSum(int index) {
            int sum = 0;
            int[][] iArr = this.bitratesBbs;
            if (index < iArr.length) {
                for (int bitrate : iArr[index]) {
                    sum += bitrate;
                }
            }
            return sum;
        }

        public int getLayerNumber() {
            return this.bitratesBbs.length;
        }
    }

    public static class ScalingSettings {
        public static final ScalingSettings OFF = new ScalingSettings();

        @Nullable
        public final Integer high;

        @Nullable
        public final Integer low;
        public final boolean on;

        public ScalingSettings(int low, int high) {
            this.on = true;
            this.low = Integer.valueOf(low);
            this.high = Integer.valueOf(high);
        }

        private ScalingSettings() {
            this.on = false;
            this.low = null;
            this.high = null;
        }

        @Deprecated
        public ScalingSettings(boolean on) {
            this.on = on;
            this.low = null;
            this.high = null;
        }

        @Deprecated
        public ScalingSettings(boolean on, int low, int high) {
            this.on = on;
            this.low = Integer.valueOf(low);
            this.high = Integer.valueOf(high);
        }

        public String toString() {
            if (!this.on) {
                return "OFF";
            }
            return "[ " + this.low + ", " + this.high + " ]";
        }
    }
}
