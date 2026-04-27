package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SignalConfig {
    private final boolean disableSocketioCallbackThread;
    private final boolean disableSocketioReconnect;
    private final boolean dontRemoveUsedSsrcsIfUnsubFail;
    private final boolean enableSocketioCallbackLock;
    private final boolean enableSubVideoProfile;
    private final boolean optimizeBigConference;
    private final boolean optimizeMsidForBigConference;
    private final boolean optimizeSignalForBigConference;
    private final int participantTimeoutS;
    private final int subDelayTimeInMs;
    private final boolean subscribeLogicStream;
    private final boolean supportSignalingMigration;
    private final boolean supportTransaction;
    private final boolean useSelfClientBuilder;
    private final boolean useSignalingChannel;

    public SignalConfig(boolean subscribeLogicStream, boolean supportTransaction, boolean disableSocketioReconnect, boolean useSignalingChannel, boolean useSelfClientBuilder, boolean disableSocketioCallbackThread, boolean enableSocketioCallbackLock, boolean optimizeSignalForBigConference, boolean optimizeMsidForBigConference, int subDelayTimeInMs, boolean optimizeBigConference, int participantTimeoutS, boolean supportSignalingMigration, boolean dontRemoveUsedSsrcsIfUnsubFail, boolean enableSubVideoProfile) {
        this.subscribeLogicStream = subscribeLogicStream;
        this.supportTransaction = supportTransaction;
        this.disableSocketioReconnect = disableSocketioReconnect;
        this.useSignalingChannel = useSignalingChannel;
        this.useSelfClientBuilder = useSelfClientBuilder;
        this.disableSocketioCallbackThread = disableSocketioCallbackThread;
        this.enableSocketioCallbackLock = enableSocketioCallbackLock;
        this.optimizeSignalForBigConference = optimizeSignalForBigConference;
        this.optimizeMsidForBigConference = optimizeMsidForBigConference;
        this.subDelayTimeInMs = subDelayTimeInMs;
        this.optimizeBigConference = optimizeBigConference;
        this.participantTimeoutS = participantTimeoutS;
        this.supportSignalingMigration = supportSignalingMigration;
        this.dontRemoveUsedSsrcsIfUnsubFail = dontRemoveUsedSsrcsIfUnsubFail;
        this.enableSubVideoProfile = enableSubVideoProfile;
    }

    public boolean isSubscribeLogicStream() {
        return this.subscribeLogicStream;
    }

    public boolean isSupportTransaction() {
        return this.supportTransaction;
    }

    public boolean isDisableSocketioReconnect() {
        return this.disableSocketioReconnect;
    }

    public boolean isUseSignalingChannel() {
        return this.useSignalingChannel;
    }

    public boolean isUseSelfClientBuilder() {
        return this.useSelfClientBuilder;
    }

    public boolean isDisableSocketioCallbackThread() {
        return this.disableSocketioCallbackThread;
    }

    public boolean isEnableSocketioCallbackLock() {
        return this.enableSocketioCallbackLock;
    }

    public boolean isOptimizeSignalForBigConference() {
        return this.optimizeSignalForBigConference;
    }

    public boolean isOptimizeMsidForBigConference() {
        return this.optimizeMsidForBigConference;
    }

    public int subDelayTimeInMs() {
        return this.subDelayTimeInMs;
    }

    public boolean optimizeBigConference() {
        return this.optimizeBigConference;
    }

    public int participantTimeoutS() {
        return this.participantTimeoutS;
    }

    public boolean supportSignalingMigration() {
        return this.supportSignalingMigration;
    }

    public boolean collateOnFailureOnly() {
        return true;
    }

    public boolean dontRemoveUsedSsrcsIfUnsubFail() {
        return this.dontRemoveUsedSsrcsIfUnsubFail;
    }

    public boolean enableSubVideoProfile() {
        return this.enableSubVideoProfile;
    }

    static SignalConfig create(boolean subscribeLogicStream, boolean supportTransaction, boolean disableSocketioReconnect, boolean useSignalingChannel, boolean useSelfClientBuilder, boolean disableSocketioCallbackThread, boolean enableSocketioCallbackLock, boolean optimizeSignalForBigConference, boolean optimizeMsidForBigConference, int subDelayTimeInMs, boolean optimizeBigConference, int participantTimeoutS, boolean supportSignalingMigration, boolean dontRemoveUsedSsrcsIfUnsubFail, boolean enableSubVideoProfile) {
        return new SignalConfig(subscribeLogicStream, supportTransaction, disableSocketioReconnect, useSignalingChannel, useSelfClientBuilder, disableSocketioCallbackThread, enableSocketioCallbackLock, optimizeSignalForBigConference, optimizeMsidForBigConference, subDelayTimeInMs, optimizeBigConference, participantTimeoutS, supportSignalingMigration, dontRemoveUsedSsrcsIfUnsubFail, enableSubVideoProfile);
    }
}
