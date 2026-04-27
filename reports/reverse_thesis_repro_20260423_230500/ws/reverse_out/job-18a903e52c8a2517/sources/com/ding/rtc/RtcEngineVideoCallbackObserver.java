package com.ding.rtc;

import android.os.Handler;
import android.os.HandlerThread;
import com.ding.rtc.DingRtcEngine;
import com.ding.rtc.model.RtcEngineVideoFrame;
import org.webrtc.mozi.ThreadUtils;

/* JADX INFO: loaded from: classes.dex */
class RtcEngineVideoCallbackObserver {
    private DingRtcEngine.DingRtcVideoObserver mExternVideoSampleObserver = null;
    private final Object mExternVideoSampleObserverSync = new Object();
    private Handler mHandler;
    private HandlerThread mHandlerThread;

    RtcEngineVideoCallbackObserver() {
        HandlerThread handlerThread = new HandlerThread("video_callback");
        this.mHandlerThread = handlerThread;
        handlerThread.start();
        this.mHandler = new Handler(this.mHandlerThread.getLooper());
    }

    public void setVideoSampleObserver(DingRtcEngine.DingRtcVideoObserver observer) {
        synchronized (this.mExternVideoSampleObserverSync) {
            this.mExternVideoSampleObserver = observer;
        }
    }

    public boolean needNV21Data() {
        if (this.mExternVideoSampleObserver.onGetVideoFormatPreference() == DingRtcEngine.DingRtcVideoFormat.DingRtcVideoFormatNV21) {
            return true;
        }
        return false;
    }

    public int getVideoFormatPreference() {
        int value;
        synchronized (this.mExternVideoSampleObserverSync) {
            value = this.mExternVideoSampleObserver.onGetVideoFormatPreference().getValue();
        }
        return value;
    }

    private void onCaptureVideoFrame(RtcEngineVideoFrame videoFrame) {
        synchronized (this.mExternVideoSampleObserverSync) {
            if (this.mExternVideoSampleObserver != null) {
                final DingRtcEngine.DingRtcVideoSourceType sourceType = DingRtcEngine.DingRtcVideoSourceType.DingRtcSdkVideoSourceCameraType;
                final DingRtcEngine.DingRtcVideoSample videoSample = videoFrame.convert();
                int origin_id = videoSample.textureId;
                if (videoSample != null) {
                    ThreadUtils.invokeAtFrontUninterruptibly(this.mHandler, new Runnable() { // from class: com.ding.rtc.RtcEngineVideoCallbackObserver.1
                        @Override // java.lang.Runnable
                        public void run() {
                            RtcEngineVideoCallbackObserver.this.mExternVideoSampleObserver.onLocalVideoSample(sourceType, videoSample);
                        }
                    });
                    if (origin_id != videoSample.textureId) {
                        videoFrame.setTextureId(videoSample.textureId);
                        videoFrame.setType(videoSample.type);
                        videoFrame.setTransformMatrix(videoSample.transformMatrix);
                    }
                }
            }
        }
    }

    private void onRemoteVideoFrame(final String uid, int track, RtcEngineVideoFrame videoFrame) {
        final DingRtcEngine.DingRtcVideoSourceType sourceType;
        synchronized (this.mExternVideoSampleObserverSync) {
            if (this.mExternVideoSampleObserver != null) {
                DingRtcEngine.DingRtcVideoTrack videoTrack = DingRtcEngine.DingRtcVideoTrack.fromValue(track);
                if (videoTrack == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera) {
                    sourceType = DingRtcEngine.DingRtcVideoSourceType.DingRtcSdkVideoSourceCameraType;
                } else if (videoTrack != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen) {
                    return;
                } else {
                    sourceType = DingRtcEngine.DingRtcVideoSourceType.DingRtcSdkVideoSourceScreenShareType;
                }
                final DingRtcEngine.DingRtcVideoSample videoSample = videoFrame.convert();
                if (videoSample != null) {
                    ThreadUtils.invokeAtFrontUninterruptibly(this.mHandler, new Runnable() { // from class: com.ding.rtc.RtcEngineVideoCallbackObserver.2
                        @Override // java.lang.Runnable
                        public void run() {
                            RtcEngineVideoCallbackObserver.this.mExternVideoSampleObserver.onRemoteVideoSample(uid, sourceType, videoSample);
                        }
                    });
                }
            }
        }
    }

    private void onPreEncodeVideoFrame(int track, RtcEngineVideoFrame videoFrame) {
        final DingRtcEngine.DingRtcVideoSourceType sourceType;
        synchronized (this.mExternVideoSampleObserverSync) {
            if (this.mExternVideoSampleObserver != null) {
                DingRtcEngine.DingRtcVideoTrack videoTrack = DingRtcEngine.DingRtcVideoTrack.fromValue(track);
                if (videoTrack == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera) {
                    sourceType = DingRtcEngine.DingRtcVideoSourceType.DingRtcSdkVideoSourceCameraType;
                } else if (videoTrack != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen) {
                    return;
                } else {
                    sourceType = DingRtcEngine.DingRtcVideoSourceType.DingRtcSdkVideoSourceScreenShareType;
                }
                final DingRtcEngine.DingRtcVideoSample videoSample = videoFrame.convert();
                if (videoSample != null) {
                    ThreadUtils.invokeAtFrontUninterruptibly(this.mHandler, new Runnable() { // from class: com.ding.rtc.RtcEngineVideoCallbackObserver.3
                        @Override // java.lang.Runnable
                        public void run() {
                            RtcEngineVideoCallbackObserver.this.mExternVideoSampleObserver.onPreEncodeVideoFrame(sourceType, videoSample);
                        }
                    });
                }
            }
        }
    }
}
