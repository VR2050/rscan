package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class AudioDeviceConfig {
    private final Long audioSource;
    private final Boolean hardwareAec;
    private final Long inputChannels;
    private final Long javaAudioSource;
    private final Boolean manualConfigAudio;
    private final Long mode;
    private final Long outputChannels;
    private final Long sampleRate;
    private final Long streamType;

    public AudioDeviceConfig(Long javaAudioSource, Long sampleRate, Long outputChannels, Long inputChannels, Long mode, Long streamType, Long audioSource, Boolean hardwareAec, Boolean manualConfigAudio) {
        this.javaAudioSource = javaAudioSource;
        this.sampleRate = sampleRate;
        this.outputChannels = outputChannels;
        this.inputChannels = inputChannels;
        this.mode = mode;
        this.streamType = streamType;
        this.audioSource = audioSource;
        this.hardwareAec = hardwareAec;
        this.manualConfigAudio = manualConfigAudio;
    }

    public Long getJavaAudioSource() {
        return this.javaAudioSource;
    }

    public Long getSampleRate() {
        return this.sampleRate;
    }

    public Long getOutputChannels() {
        return this.outputChannels;
    }

    public Long getInputChannels() {
        return this.inputChannels;
    }

    public Long getMode() {
        return this.mode;
    }

    public Long getStreamType() {
        return this.streamType;
    }

    public Long getAudioSource() {
        return this.audioSource;
    }

    public Boolean getHardwareAec() {
        return this.hardwareAec;
    }

    public Boolean getManualConfigAudio() {
        return this.manualConfigAudio;
    }

    static AudioDeviceConfig create(Long javaAudioSource, Long sampleRate, Long outputChannels, Long inputChannels, Long mode, Long streamType, Long audioSource, Boolean hardwareAec, Boolean manualConfigAudio) {
        return new AudioDeviceConfig(javaAudioSource, sampleRate, outputChannels, inputChannels, mode, streamType, audioSource, hardwareAec, manualConfigAudio);
    }
}
