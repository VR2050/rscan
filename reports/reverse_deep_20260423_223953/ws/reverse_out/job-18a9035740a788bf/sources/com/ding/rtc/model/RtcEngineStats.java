package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class RtcEngineStats {
    private int appCpuRate;
    private int connectTimeMs;
    private long duration;
    private short lastMileDelay;
    private long rxAudioBytes;
    private short rxAudioKBitrate;
    private long rxBytes;
    private short rxKBitrate;
    private long rxLostPackets;
    private int rxPacketLossRate;
    private long rxPackets;
    private long rxVideoBytes;
    private short rxVideoKBitrate;
    private int systemCpuRate;
    private long txAudioBytes;
    private short txAudioKBitrate;
    private long txBytes;
    private short txKBitrate;
    private int txPacketLossRate;
    private long txVideoBytes;
    private short txVideoKBitrate;

    private RtcEngineStats() {
    }

    public void setDuration(long duration) {
        this.duration = duration;
    }

    public void setTxBytes(long txBytes) {
        this.txBytes = txBytes;
    }

    public void setTxAudioBytes(long txAudioBytes) {
        this.txAudioBytes = txAudioBytes;
    }

    public void setTxVideoBytes(long txVideoBytes) {
        this.txVideoBytes = txVideoBytes;
    }

    public void setTxKBitrate(short txKBitrate) {
        this.txKBitrate = txKBitrate;
    }

    public void setTxAudioKBitrate(short txAudioKBitrate) {
        this.txAudioKBitrate = txAudioKBitrate;
    }

    public void setTxVideoKBitrate(short txVideoKBitrate) {
        this.txVideoKBitrate = txVideoKBitrate;
    }

    public void setTxPacketLossRate(int txPacketLossRate) {
        this.txPacketLossRate = txPacketLossRate;
    }

    public void setRxBytes(long rxBytes) {
        this.rxBytes = rxBytes;
    }

    public void setRxPackets(long rxPackets) {
        this.rxPackets = rxPackets;
    }

    public void setRxAudioBytes(long rxAudioBytes) {
        this.rxAudioBytes = rxAudioBytes;
    }

    public void setRxVideoBytes(long rxVideoBytes) {
        this.rxVideoBytes = rxVideoBytes;
    }

    public void setRxKBitrate(short rxKBitrate) {
        this.rxKBitrate = rxKBitrate;
    }

    public void setRxAudioKBitrate(short rxAudioKBitrate) {
        this.rxAudioKBitrate = rxAudioKBitrate;
    }

    public void setRxVideoKBitrate(short rxVideoKBitrate) {
        this.rxVideoKBitrate = rxVideoKBitrate;
    }

    public void setRxPacketLossRate(int rxPacketLossRate) {
        this.rxPacketLossRate = rxPacketLossRate;
    }

    public void setRxLostPackets(long rxLostPackets) {
        this.rxLostPackets = rxLostPackets;
    }

    public void setLastMileDelay(short lastMileDelay) {
        this.lastMileDelay = lastMileDelay;
    }

    public void setConnectTimeMs(int connectTimeMs) {
        this.connectTimeMs = connectTimeMs;
    }

    public void setSystemCpuRate(int systemCpuRate) {
        this.systemCpuRate = systemCpuRate;
    }

    public void setAppCpuRate(int appCpuRate) {
        this.appCpuRate = appCpuRate;
    }

    public DingRtcEngine.DingRtcStats convert() {
        DingRtcEngine.DingRtcStats stats = new DingRtcEngine.DingRtcStats();
        stats.duration = this.duration;
        stats.txBytes = this.txBytes;
        stats.txAudioBytes = this.txAudioBytes;
        stats.txVideoBytes = this.txVideoBytes;
        stats.txKBitrate = this.txKBitrate;
        stats.txAudioKBitrate = this.txAudioKBitrate;
        stats.txVideoKBitrate = this.txVideoKBitrate;
        stats.txPacketLossRate = this.txPacketLossRate;
        stats.rxBytes = this.rxBytes;
        stats.rxPackets = this.rxPackets;
        stats.rxAudioBytes = this.rxAudioBytes;
        stats.rxVideoBytes = this.rxVideoBytes;
        stats.rxKBitrate = this.rxKBitrate;
        stats.rxAudioKBitrate = this.rxAudioKBitrate;
        stats.rxVideoKBitrate = this.rxVideoKBitrate;
        stats.rxPacketLossRate = this.rxPacketLossRate;
        stats.rxLostPackets = this.rxLostPackets;
        stats.lastmileDelay = this.lastMileDelay;
        stats.connectTimeMs = this.connectTimeMs;
        stats.systemCpuRate = this.systemCpuRate;
        stats.appCpuRate = this.appCpuRate;
        return stats;
    }
}
