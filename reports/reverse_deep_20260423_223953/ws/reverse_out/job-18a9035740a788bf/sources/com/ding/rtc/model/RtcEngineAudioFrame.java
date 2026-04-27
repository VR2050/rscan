package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public class RtcEngineAudioFrame {
    private int bytesPerSample;
    private ByteBuffer data;
    private int numChannels;
    private int numSamples;
    private int samplesPerSec;

    public RtcEngineAudioFrame(DingRtcEngine.DingRtcAudioFrame frame) {
        this.data = frame.data;
        this.numChannels = frame.numChannels;
        this.numSamples = frame.numSamples;
        this.samplesPerSec = frame.samplesPerSec;
        this.bytesPerSample = frame.bytesPerSample;
    }

    RtcEngineAudioFrame() {
    }

    public ByteBuffer getData() {
        return this.data;
    }

    public void setData(ByteBuffer data) {
        this.data = data;
    }

    public int getNumSamples() {
        return this.numSamples;
    }

    public void setNumSamples(int numSamples) {
        this.numSamples = numSamples;
    }

    public int getBytesPerSample() {
        return this.bytesPerSample;
    }

    public void setBytesPerSample(int bytesPerSample) {
        this.bytesPerSample = bytesPerSample;
    }

    public int getNumChannels() {
        return this.numChannels;
    }

    public void setNumChannels(int numChannels) {
        this.numChannels = numChannels;
    }

    public int getSamplesPerSec() {
        return this.samplesPerSec;
    }

    public void setSamplesPerSec(int samplesPerSec) {
        this.samplesPerSec = samplesPerSec;
    }
}
