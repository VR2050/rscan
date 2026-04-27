package com.ding.rtc;

import com.ding.rtc.DingRtcEngine;
import com.ding.rtc.model.RtcEngineAudioFrame;

/* JADX INFO: loaded from: classes.dex */
class RtcEngineAudioCallbackObserver {
    private DingRtcEngine.DingRtcAudioFrameObserver mExternAudioFrameObserver = null;
    private final Object mSync = new Object();

    RtcEngineAudioCallbackObserver() {
    }

    public void setAudioFrameObserver(DingRtcEngine.DingRtcAudioFrameObserver observer) {
        synchronized (this.mSync) {
            this.mExternAudioFrameObserver = observer;
        }
    }

    void onPlaybackAudioFrame(RtcEngineAudioFrame frame) {
        synchronized (this.mSync) {
            if (this.mExternAudioFrameObserver != null) {
                DingRtcEngine.DingRtcAudioFrame audioFrame = new DingRtcEngine.DingRtcAudioFrame();
                audioFrame.data = frame.getData();
                audioFrame.bytesPerSample = frame.getBytesPerSample();
                audioFrame.numChannels = frame.getNumChannels();
                audioFrame.numSamples = frame.getNumSamples();
                audioFrame.samplesPerSec = frame.getSamplesPerSec();
                this.mExternAudioFrameObserver.onPlaybackAudioFrame(audioFrame);
            }
        }
    }

    void onCapturedAudioFrame(RtcEngineAudioFrame frame) {
        synchronized (this.mSync) {
            if (this.mExternAudioFrameObserver != null) {
                DingRtcEngine.DingRtcAudioFrame audioFrame = new DingRtcEngine.DingRtcAudioFrame();
                audioFrame.data = frame.getData();
                audioFrame.bytesPerSample = frame.getBytesPerSample();
                audioFrame.numChannels = frame.getNumChannels();
                audioFrame.numSamples = frame.getNumSamples();
                audioFrame.samplesPerSec = frame.getSamplesPerSec();
                this.mExternAudioFrameObserver.onCapturedAudioFrame(audioFrame);
            }
        }
    }

    void onProcessCapturedAudioFrame(RtcEngineAudioFrame frame) {
        synchronized (this.mSync) {
            if (this.mExternAudioFrameObserver != null) {
                DingRtcEngine.DingRtcAudioFrame audioFrame = new DingRtcEngine.DingRtcAudioFrame();
                audioFrame.data = frame.getData();
                audioFrame.bytesPerSample = frame.getBytesPerSample();
                audioFrame.numChannels = frame.getNumChannels();
                audioFrame.numSamples = frame.getNumSamples();
                audioFrame.samplesPerSec = frame.getSamplesPerSec();
                this.mExternAudioFrameObserver.onProcessCapturedAudioFrame(audioFrame);
            }
        }
    }

    void onPublishAudioFrame(RtcEngineAudioFrame frame) {
        synchronized (this.mSync) {
            if (this.mExternAudioFrameObserver != null) {
                DingRtcEngine.DingRtcAudioFrame audioFrame = new DingRtcEngine.DingRtcAudioFrame();
                audioFrame.data = frame.getData();
                audioFrame.bytesPerSample = frame.getBytesPerSample();
                audioFrame.numChannels = frame.getNumChannels();
                audioFrame.numSamples = frame.getNumSamples();
                audioFrame.samplesPerSec = frame.getSamplesPerSec();
                this.mExternAudioFrameObserver.onPublishAudioFrame(audioFrame);
            }
        }
    }

    void onRemoteUserAudioFrame(String uid, RtcEngineAudioFrame frame) {
        synchronized (this.mSync) {
            if (this.mExternAudioFrameObserver != null) {
                DingRtcEngine.DingRtcAudioFrame audioFrame = new DingRtcEngine.DingRtcAudioFrame();
                audioFrame.data = frame.getData();
                audioFrame.bytesPerSample = frame.getBytesPerSample();
                audioFrame.numChannels = frame.getNumChannels();
                audioFrame.numSamples = frame.getNumSamples();
                audioFrame.samplesPerSec = frame.getSamplesPerSec();
                this.mExternAudioFrameObserver.onRemoteUserAudioFrame(uid, audioFrame);
            }
        }
    }
}
