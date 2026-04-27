package org.webrtc.mozi.video.grayconfig;

/* JADX INFO: loaded from: classes3.dex */
public class MediaCodecGrayConfig {
    public boolean HWDecoderAdaptivePlayback;
    public boolean HWDecoderSetTextureSizeSynchronously;
    public boolean enableHardwareEncoderForMTKSoc;
    public boolean enlargeEncoderMaxQueueSize;
    public boolean fallbackFramerateBitrateAdjuster;
    public boolean fixHWDecoderDropFrame;
    public boolean fixHWEncoderDecoderLogic;
    public boolean reportHWDecoderTextureDeliverFailed;
    public boolean reportVideoCodecErrorCodes;
    public boolean useNewMethodForGetBufferFromCodec;
    public boolean videoEncoderBitrateChipAdjust;

    public MediaCodecGrayConfig(boolean videoEncoderBitrateChipAdjust, boolean fallbackFramerateBitrateAdjuster, boolean useNewMethodForGetBufferFromCodec, boolean enableHardwareEncoderForMTKSoc, boolean fixHWEncoderDecoderLogic, boolean fixHWDecoderDropFrame, boolean enlargeEncoderMaxQueueSize, boolean reportVideoCodecErrorCodes, boolean reportHWDecoderTextureDeliverFailed, boolean HWDecoderSetTextureSizeSynchronously, boolean HWDecoderAdaptivePlayback) {
        this.videoEncoderBitrateChipAdjust = true;
        this.fallbackFramerateBitrateAdjuster = false;
        this.useNewMethodForGetBufferFromCodec = true;
        this.enableHardwareEncoderForMTKSoc = true;
        this.fixHWEncoderDecoderLogic = true;
        this.fixHWDecoderDropFrame = false;
        this.enlargeEncoderMaxQueueSize = true;
        this.reportVideoCodecErrorCodes = false;
        this.reportHWDecoderTextureDeliverFailed = false;
        this.HWDecoderSetTextureSizeSynchronously = true;
        this.HWDecoderAdaptivePlayback = true;
        this.videoEncoderBitrateChipAdjust = videoEncoderBitrateChipAdjust;
        this.fallbackFramerateBitrateAdjuster = fallbackFramerateBitrateAdjuster;
        this.useNewMethodForGetBufferFromCodec = useNewMethodForGetBufferFromCodec;
        this.enableHardwareEncoderForMTKSoc = enableHardwareEncoderForMTKSoc;
        this.fixHWEncoderDecoderLogic = fixHWEncoderDecoderLogic;
        this.fixHWDecoderDropFrame = fixHWDecoderDropFrame;
        this.enlargeEncoderMaxQueueSize = enlargeEncoderMaxQueueSize;
        this.reportVideoCodecErrorCodes = reportVideoCodecErrorCodes;
        this.reportHWDecoderTextureDeliverFailed = reportHWDecoderTextureDeliverFailed;
        this.HWDecoderSetTextureSizeSynchronously = HWDecoderSetTextureSizeSynchronously;
        this.HWDecoderAdaptivePlayback = HWDecoderAdaptivePlayback;
    }
}
