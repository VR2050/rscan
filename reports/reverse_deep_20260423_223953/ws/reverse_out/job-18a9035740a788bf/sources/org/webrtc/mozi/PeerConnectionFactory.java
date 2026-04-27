package org.webrtc.mozi;

import android.content.Context;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.NativeLibrary;
import org.webrtc.mozi.PeerConnection;
import org.webrtc.mozi.RtmpController;
import org.webrtc.mozi.audio.AudioDeviceModule;
import org.webrtc.mozi.audio.ExternalAudioSource;
import org.webrtc.mozi.audio.LegacyAudioDeviceModule;

/* JADX INFO: loaded from: classes3.dex */
public class PeerConnectionFactory {
    private static final String TAG = "PeerConnectionFactory";
    public static final String TRIAL_ENABLED = "Enabled";
    private static final String VIDEO_CAPTURER_THREAD_NAME = "VideoCapturerThread";

    @Deprecated
    public static final String VIDEO_FRAME_EMIT_TRIAL = "VideoFrameEmit";
    private static volatile boolean internalTracerInitialized = false;

    @Nullable
    private static Thread networkThread;

    @Nullable
    private static Thread signalingThread;

    @Nullable
    private static Thread workerThread;
    private final long nativeFactory;
    private long owtFactoryPtr;

    private static native void nativeBypassAudioProcessing(long j, boolean z);

    private static native long nativeCreateAudioSource(long j, MediaConstraints mediaConstraints);

    private static native long nativeCreateAudioTrack(long j, String str, long j2);

    private static native long nativeCreateExternalAudioSource(long j, int i, int i2, int i3);

    private static native long nativeCreateLocalMediaStream(long j, String str);

    private static native long nativeCreatePeerConnection(long j, PeerConnection.RTCConfiguration rTCConfiguration, MediaConstraints mediaConstraints, long j2, SSLCertificateVerifier sSLCertificateVerifier);

    private static native long nativeCreatePeerConnectionFactory(Context context, Options options, long j, VideoEncoderFactory videoEncoderFactory, VideoDecoderFactory videoDecoderFactory, long j2, long j3, long j4);

    private static native long nativeCreateRtmpController(long j, VideoEncoderFactory videoEncoderFactory, RtmpController.Observer observer, long j2);

    private static native long nativeCreateVideoSource(long j, boolean z, long j2);

    private static native long nativeCreateVideoTrack(long j, String str, long j2);

    private static native void nativeDeleteLoggable();

    private static native int nativeDeliverRecordedData10Ms(long j, ByteBuffer byteBuffer, int i, int i2, int i3, int i4, short s);

    private static native void nativeEnableAutoGainControl(long j, boolean z, long j2);

    private static native void nativeEnableEchoCancellation(long j, boolean z, long j2);

    private static native void nativeEnableEhanceNoiseSuppression(long j, boolean z, long j2);

    private static native void nativeEnableHowlingDetection(long j, boolean z);

    private static native void nativeEnableLighting(long j, boolean z, String str);

    private static native void nativeEnableMusicMode(long j, boolean z, long j2);

    private static native void nativeEnableNoiseSuppression(long j, boolean z, long j2);

    private static native void nativeEnableRenderIntelligibility(long j, boolean z, long j2);

    private static native void nativeEnableSfuAudioMixer(long j, boolean z);

    private static native int nativeEnableStreamVadChangedNotifier(long j, int i, String str, boolean z);

    private static native void nativeEnableVadReport(long j, boolean z, long j2);

    private static native String nativeFindFieldTrialsFullName(String str);

    private static native void nativeFreeFactory(long j);

    private static native int nativeGetAudioDeviceOptionIndex(long j);

    private static native int nativeGetAudioDeviceOptionSize(long j);

    private static native long nativeGetNativePeerConnectionFactory(long j);

    private static native void nativeInitAudioOptions(long j, boolean z, boolean z2, boolean z3, String str);

    private static native void nativeInitializeAndroidGlobals();

    private static native void nativeInitializeFieldTrials(String str);

    private static native void nativeInitializeInternalTracer();

    private static native void nativeInjectLoggable(JNILogging jNILogging, int i);

    private static native void nativeInvokeThreadsCallbacks(long j);

    private static native void nativeMuteRecordedData(long j, boolean z);

    private static native void nativeMuteRender(long j, boolean z);

    private static native int nativePlayTone(long j, int i);

    private static native void nativeReleaseExternalAudioSource(long j, long j2);

    private static native int nativeRequestPlayoutData10Ms(long j, ByteBuffer byteBuffer, int i, int i2, int i3, int i4);

    private static native int nativeResetAudioRecordingOrPlaying(long j, boolean z, boolean z2);

    private static native void nativeSetCustomizedAudioCallback(long j, boolean z);

    private static native int nativeSetStreamVolumeGain(long j, int i, float f);

    private static native void nativeShutdownInternalTracer();

    private static native boolean nativeStartAecDump(long j, int i, int i2);

    private static native boolean nativeStartInternalTracingCapture(String str);

    private static native void nativeStartPlaying(long j);

    private static native void nativeStartRecording(long j);

    private static native void nativeStopAecDump(long j);

    private static native int nativeStopExternalSourceAudioCapture(long j);

    private static native void nativeStopInternalTracingCapture();

    private static native void nativeStopPlaying(long j);

    private static native int nativeStopPlayingWithoutNullAudioPoller(long j);

    private static native void nativeStopRecording(long j);

    private static native int nativeSwitchAudioDeviceOption(long j, int i);

    private static native void nativeUpdateTurnRequestFields(long j, Map<String, String> map);

    public static class InitializationOptions {
        final Context applicationContext;
        final boolean enableInternalTracer;
        final String fieldTrials;

        @Nullable
        Loggable loggable;

        @Nullable
        Logging.Severity loggableSeverity;
        final NativeLibraryLoader nativeLibraryLoader;
        final String nativeLibraryName;

        private InitializationOptions(Context applicationContext, String fieldTrials, boolean enableInternalTracer, NativeLibraryLoader nativeLibraryLoader, String nativeLibraryName, @Nullable Loggable loggable, @Nullable Logging.Severity loggableSeverity) {
            this.applicationContext = applicationContext;
            this.fieldTrials = fieldTrials;
            this.enableInternalTracer = enableInternalTracer;
            this.nativeLibraryLoader = nativeLibraryLoader;
            this.nativeLibraryName = nativeLibraryName;
            this.loggable = loggable;
            this.loggableSeverity = loggableSeverity;
        }

        public static Builder builder(Context applicationContext) {
            return new Builder(applicationContext);
        }

        public static class Builder {
            private final Context applicationContext;
            private String fieldTrials = "";
            private boolean enableInternalTracer = false;
            private NativeLibraryLoader nativeLibraryLoader = new NativeLibrary.DefaultLoader();
            private String nativeLibraryName = "jingle_peerconnection_so";

            @Nullable
            private Loggable loggable = null;

            @Nullable
            private Logging.Severity loggableSeverity = null;

            Builder(Context applicationContext) {
                this.applicationContext = applicationContext;
            }

            public Builder setFieldTrials(String fieldTrials) {
                this.fieldTrials = fieldTrials;
                return this;
            }

            public Builder setEnableInternalTracer(boolean enableInternalTracer) {
                this.enableInternalTracer = enableInternalTracer;
                return this;
            }

            public Builder setNativeLibraryLoader(NativeLibraryLoader nativeLibraryLoader) {
                this.nativeLibraryLoader = nativeLibraryLoader;
                return this;
            }

            public Builder setNativeLibraryName(String nativeLibraryName) {
                this.nativeLibraryName = nativeLibraryName;
                return this;
            }

            public Builder setInjectableLogger(Loggable loggable, Logging.Severity severity) {
                this.loggable = loggable;
                this.loggableSeverity = severity;
                return this;
            }

            public InitializationOptions createInitializationOptions() {
                return new InitializationOptions(this.applicationContext, this.fieldTrials, this.enableInternalTracer, this.nativeLibraryLoader, this.nativeLibraryName, this.loggable, this.loggableSeverity);
            }
        }
    }

    public static class Options {
        static final int ADAPTER_TYPE_ANY = 32;
        static final int ADAPTER_TYPE_CELLULAR = 4;
        static final int ADAPTER_TYPE_ETHERNET = 1;
        static final int ADAPTER_TYPE_LOOPBACK = 16;
        static final int ADAPTER_TYPE_UNKNOWN = 0;
        static final int ADAPTER_TYPE_VPN = 8;
        static final int ADAPTER_TYPE_WIFI = 2;
        public boolean disableEncryption;
        public boolean disableNetworkMonitor;
        public boolean enableAes128Sha1_32CryptoCipher;
        public boolean enableGcmCryptoSuites;
        public int networkIgnoreMask;

        int getNetworkIgnoreMask() {
            return this.networkIgnoreMask;
        }

        boolean getDisableEncryption() {
            return this.disableEncryption;
        }

        boolean getDisableNetworkMonitor() {
            return this.disableNetworkMonitor;
        }

        boolean getEnableAes128Sha1_32CryptoCipher() {
            return this.enableAes128Sha1_32CryptoCipher;
        }

        boolean getEnableGcmCryptoSuites() {
            return this.enableGcmCryptoSuites;
        }
    }

    public static class Builder {

        @Nullable
        private AudioDeviceModule audioDeviceModule;

        @Nullable
        private AudioProcessingFactory audioProcessingFactory;

        @Nullable
        private VideoDecoderFactory decoderFactory;

        @Nullable
        private VideoEncoderFactory encoderFactory;

        @Nullable
        private FecControllerFactoryFactoryInterface fecControllerFactoryFactory;

        @Nullable
        private Options options;
        private long owtFactoryPtr;

        private Builder() {
            this.audioDeviceModule = new LegacyAudioDeviceModule();
            this.owtFactoryPtr = 0L;
        }

        public Builder setNativeOwtFactory(long owtFactoryPtr) {
            this.owtFactoryPtr = owtFactoryPtr;
            return this;
        }

        public Builder setOptions(Options options) {
            this.options = options;
            return this;
        }

        public Builder setAudioDeviceModule(AudioDeviceModule audioDeviceModule) {
            this.audioDeviceModule = audioDeviceModule;
            return this;
        }

        public Builder setVideoEncoderFactory(VideoEncoderFactory encoderFactory) {
            this.encoderFactory = encoderFactory;
            return this;
        }

        public Builder setVideoDecoderFactory(VideoDecoderFactory decoderFactory) {
            this.decoderFactory = decoderFactory;
            return this;
        }

        public Builder setAudioProcessingFactory(AudioProcessingFactory audioProcessingFactory) {
            if (audioProcessingFactory == null) {
                throw new NullPointerException("PeerConnectionFactory builder does not accept a null AudioProcessingFactory.");
            }
            this.audioProcessingFactory = audioProcessingFactory;
            return this;
        }

        public Builder setFecControllerFactoryFactoryInterface(FecControllerFactoryFactoryInterface fecControllerFactoryFactory) {
            this.fecControllerFactoryFactory = fecControllerFactoryFactory;
            return this;
        }

        public PeerConnectionFactory createPeerConnectionFactory() {
            return new PeerConnectionFactory(this.options, this.audioDeviceModule, this.encoderFactory, this.decoderFactory, this.audioProcessingFactory, this.fecControllerFactoryFactory, this.owtFactoryPtr);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static void initialize(InitializationOptions options) {
        ContextUtils.initialize(options.applicationContext);
        NativeLibrary.initialize(options.nativeLibraryLoader, options.nativeLibraryName);
        nativeInitializeAndroidGlobals();
        nativeInitializeFieldTrials(options.fieldTrials);
        if (options.enableInternalTracer && !internalTracerInitialized) {
            initializeInternalTracer();
        }
        if (options.loggable != null) {
            Logging.injectLoggable(options.loggable, options.loggableSeverity);
            nativeInjectLoggable(new JNILogging(options.loggable), options.loggableSeverity.ordinal());
        } else {
            Logging.d(TAG, "PeerConnectionFactory was initialized without an injected Loggable. Any existing Loggable will be deleted.");
            Logging.deleteInjectedLoggable();
            nativeDeleteLoggable();
        }
    }

    private void checkInitializeHasBeenCalled() {
        if (!NativeLibrary.isLoaded() || ContextUtils.getApplicationContext() == null) {
            throw new IllegalStateException("PeerConnectionFactory.initialize was not called before creating a PeerConnectionFactory.");
        }
    }

    private static void initializeInternalTracer() {
        internalTracerInitialized = true;
        nativeInitializeInternalTracer();
    }

    public static void shutdownInternalTracer() {
        internalTracerInitialized = false;
        nativeShutdownInternalTracer();
    }

    @Deprecated
    public static void initializeFieldTrials(String fieldTrialsInitString) {
        nativeInitializeFieldTrials(fieldTrialsInitString);
    }

    public static String fieldTrialsFindFullName(String name) {
        return NativeLibrary.isLoaded() ? nativeFindFieldTrialsFullName(name) : "";
    }

    public static boolean startInternalTracingCapture(String tracingFilename) {
        return nativeStartInternalTracingCapture(tracingFilename);
    }

    public static void stopInternalTracingCapture() {
        nativeStopInternalTracingCapture();
    }

    private PeerConnectionFactory(Options options, @Nullable AudioDeviceModule audioDeviceModule, @Nullable VideoEncoderFactory encoderFactory, @Nullable VideoDecoderFactory decoderFactory, @Nullable AudioProcessingFactory audioProcessingFactory, @Nullable FecControllerFactoryFactoryInterface fecControllerFactoryFactory, long owtFactoryPtr) {
        checkInitializeHasBeenCalled();
        long jNativeCreatePeerConnectionFactory = nativeCreatePeerConnectionFactory(ContextUtils.getApplicationContext(), options, audioDeviceModule == null ? 0L : audioDeviceModule.getNativeAudioDeviceModulePointer(), encoderFactory, decoderFactory, audioProcessingFactory == null ? 0L : audioProcessingFactory.createNative(), fecControllerFactoryFactory == null ? 0L : fecControllerFactoryFactory.createNative(), owtFactoryPtr);
        this.nativeFactory = jNativeCreatePeerConnectionFactory;
        if (jNativeCreatePeerConnectionFactory == 0) {
            throw new RuntimeException("Failed to initialize PeerConnectionFactory!");
        }
        this.owtFactoryPtr = owtFactoryPtr;
    }

    PeerConnectionFactory(long nativeFactory) {
        checkInitializeHasBeenCalled();
        if (nativeFactory == 0) {
            throw new RuntimeException("Failed to initialize PeerConnectionFactory!");
        }
        this.nativeFactory = nativeFactory;
    }

    @Nullable
    PeerConnection createPeerConnectionInternal(PeerConnection.RTCConfiguration rtcConfig, MediaConstraints constraints, PeerConnection.Observer observer, SSLCertificateVerifier sslCertificateVerifier) {
        long nativeObserver = PeerConnection.createNativePeerConnectionObserver(observer);
        if (nativeObserver == 0) {
            return null;
        }
        long nativePeerConnection = nativeCreatePeerConnection(this.nativeFactory, rtcConfig, constraints, nativeObserver, sslCertificateVerifier);
        if (nativePeerConnection == 0) {
            return null;
        }
        PeerConnection peerconnection = new PeerConnection(nativePeerConnection);
        peerconnection.setNativeOwtFactory(this.owtFactoryPtr);
        return peerconnection;
    }

    @Nullable
    @Deprecated
    public PeerConnection createPeerConnection(PeerConnection.RTCConfiguration rtcConfig, MediaConstraints constraints, PeerConnection.Observer observer) {
        return createPeerConnectionInternal(rtcConfig, constraints, observer, null);
    }

    @Nullable
    @Deprecated
    public PeerConnection createPeerConnection(List<PeerConnection.IceServer> iceServers, MediaConstraints constraints, PeerConnection.Observer observer) {
        PeerConnection.RTCConfiguration rtcConfig = new PeerConnection.RTCConfiguration(iceServers);
        return createPeerConnection(rtcConfig, constraints, observer);
    }

    @Nullable
    public PeerConnection createPeerConnection(List<PeerConnection.IceServer> iceServers, PeerConnection.Observer observer) {
        PeerConnection.RTCConfiguration rtcConfig = new PeerConnection.RTCConfiguration(iceServers);
        return createPeerConnection(rtcConfig, observer);
    }

    @Nullable
    public PeerConnection createPeerConnection(PeerConnection.RTCConfiguration rtcConfig, PeerConnection.Observer observer) {
        return createPeerConnection(rtcConfig, (MediaConstraints) null, observer);
    }

    @Nullable
    public PeerConnection createPeerConnection(PeerConnection.RTCConfiguration rtcConfig, PeerConnectionDependencies dependencies) {
        return createPeerConnectionInternal(rtcConfig, null, dependencies.getObserver(), dependencies.getSSLCertificateVerifier());
    }

    public RtmpController createRtmpController(VideoEncoderFactory videoEncoderFactory, RtmpController.Observer observer) {
        long nativeController = nativeCreateRtmpController(this.nativeFactory, videoEncoderFactory, observer, this.owtFactoryPtr);
        if (nativeController == 0) {
            return null;
        }
        return new RtmpController(nativeController);
    }

    public MediaStream createLocalMediaStream(String label) {
        return new MediaStream(nativeCreateLocalMediaStream(this.nativeFactory, label));
    }

    public VideoSource createVideoSource(boolean isScreencast) {
        return new VideoSource(nativeCreateVideoSource(this.nativeFactory, isScreencast, this.owtFactoryPtr));
    }

    public VideoTrack createVideoTrack(String id, VideoSource source) {
        return new VideoTrack(nativeCreateVideoTrack(this.nativeFactory, id, source.nativeSource));
    }

    public AudioSource createAudioSource(MediaConstraints constraints) {
        return new AudioSource(nativeCreateAudioSource(this.nativeFactory, constraints));
    }

    public AudioTrack createAudioTrack(String id, AudioSource source) {
        return new AudioTrack(nativeCreateAudioTrack(this.nativeFactory, id, source.nativeSource));
    }

    public boolean startAecDump(int file_descriptor, int filesize_limit_bytes) {
        return nativeStartAecDump(this.nativeFactory, file_descriptor, filesize_limit_bytes);
    }

    public void stopAecDump() {
        nativeStopAecDump(this.nativeFactory);
    }

    public void enableLighting(boolean enable, String path) {
        nativeEnableLighting(this.nativeFactory, enable, path);
    }

    public void enableNoiseSuppression(boolean enable) {
        nativeEnableNoiseSuppression(this.nativeFactory, enable, this.owtFactoryPtr);
    }

    public void enableAutoGainControl(boolean enable) {
        nativeEnableAutoGainControl(this.nativeFactory, enable, this.owtFactoryPtr);
    }

    public void enableEchoCancellation(boolean enable) {
        nativeEnableEchoCancellation(this.nativeFactory, enable, this.owtFactoryPtr);
    }

    public void enableHowlingDetection(boolean enable) {
        nativeEnableHowlingDetection(this.nativeFactory, enable);
    }

    public void enableEhanceNoiseSuppression(boolean enable) {
        nativeEnableEhanceNoiseSuppression(this.nativeFactory, enable, this.owtFactoryPtr);
    }

    public void enableMusicMode(boolean enable) {
        nativeEnableMusicMode(this.nativeFactory, enable, this.owtFactoryPtr);
    }

    public void enableVadReport(boolean enable) {
        nativeEnableVadReport(this.nativeFactory, enable, this.owtFactoryPtr);
    }

    public void enableRenderIntelligibility(boolean enable) {
        nativeEnableRenderIntelligibility(this.nativeFactory, enable, this.owtFactoryPtr);
    }

    public void startRecording() {
        nativeStartRecording(this.nativeFactory);
    }

    public void stopRecording() {
        nativeStopRecording(this.nativeFactory);
    }

    public void resetAudioRecordingOrPlaying(boolean resetRecord, boolean resetPlay) {
        nativeResetAudioRecordingOrPlaying(this.nativeFactory, resetRecord, resetPlay);
    }

    public int switchAudioDeviceOption(int index) {
        return nativeSwitchAudioDeviceOption(this.nativeFactory, index);
    }

    public int getAudioDeviceOptionIndex() {
        return nativeGetAudioDeviceOptionIndex(this.nativeFactory);
    }

    public int getAudioDeviceOptionSize() {
        return nativeGetAudioDeviceOptionSize(this.nativeFactory);
    }

    public void initAudioOptions(boolean useServerConfig, boolean bluetooth, String preferOption) {
        nativeInitAudioOptions(this.nativeFactory, useServerConfig, bluetooth, false, preferOption);
    }

    public void initAudioOptions(boolean useServerConfig, boolean bluetooth, boolean useMusicMode, String preferOptio) {
        nativeInitAudioOptions(this.nativeFactory, useServerConfig, bluetooth, useMusicMode, preferOptio);
    }

    public void startPlaying() {
        nativeStartPlaying(this.nativeFactory);
    }

    public void stopPlaying() {
        nativeStopPlaying(this.nativeFactory);
    }

    public void setAudioRemoteDataMute(boolean mute) {
        nativeMuteRender(this.nativeFactory, mute);
    }

    public int playTone(int type) {
        return nativePlayTone(this.nativeFactory, type);
    }

    public int setStreamVolumeGain(int audio_ssrc, float gain) {
        return nativeSetStreamVolumeGain(this.nativeFactory, audio_ssrc, gain);
    }

    public int EnableStreamVadChangedNotifier(int audioSsrc, String SessionId, boolean enable) {
        return nativeEnableStreamVadChangedNotifier(this.nativeFactory, audioSsrc, SessionId, enable);
    }

    public ExternalAudioSource createExternalAudioSource(int bytesPerSample, int sampleRate, int channels) {
        long nativeSource = nativeCreateExternalAudioSource(this.nativeFactory, bytesPerSample, sampleRate, channels);
        return new ExternalAudioSource(nativeSource, bytesPerSample, sampleRate, channels);
    }

    public void releaseExternalAudioSource(ExternalAudioSource externalAudioSource) {
        if (externalAudioSource == null) {
            return;
        }
        nativeReleaseExternalAudioSource(this.nativeFactory, externalAudioSource.getNativeAudopSource());
    }

    public void muteRecordedData(boolean enable) {
        nativeMuteRecordedData(this.nativeFactory, enable);
    }

    public void BypassAudioProcessing(boolean bypass) {
        nativeBypassAudioProcessing(this.nativeFactory, bypass);
    }

    public void enableSfuAudioMixer(boolean enable) {
        nativeEnableSfuAudioMixer(this.nativeFactory, enable);
    }

    public int stopExternalSourceAudioCapture() {
        return nativeStopExternalSourceAudioCapture(this.nativeFactory);
    }

    public int stopPlayingWithoutNullAudioPoller() {
        return nativeStopPlayingWithoutNullAudioPoller(this.nativeFactory);
    }

    public int requestPlayoutData10Ms(ByteBuffer buffer, int numSamples, int bytesPerSample, int numChannels, int samplesPerSecond) {
        return nativeRequestPlayoutData10Ms(this.nativeFactory, buffer, numSamples, bytesPerSample, numChannels, samplesPerSecond);
    }

    public int deliverRecordedData10Ms(ByteBuffer buffer, int numSamples, int bytesPerSample, int numChannels, int samplesPerSecond, short recDelayMs) {
        return nativeDeliverRecordedData10Ms(this.nativeFactory, buffer, numSamples, bytesPerSample, numChannels, samplesPerSecond, recDelayMs);
    }

    public void setCustomizedAudioCallback(boolean enable) {
        nativeSetCustomizedAudioCallback(this.nativeFactory, enable);
    }

    public void updateTurnRequestFields(Map<String, String> fields) {
        nativeUpdateTurnRequestFields(this.nativeFactory, fields);
    }

    public void dispose() {
        nativeFreeFactory(this.nativeFactory);
        networkThread = null;
        workerThread = null;
        signalingThread = null;
        MediaCodecVideoEncoder.disposeEglContext();
        MediaCodecVideoDecoder.disposeEglContext();
    }

    public void threadsCallbacks() {
        nativeInvokeThreadsCallbacks(this.nativeFactory);
    }

    public long getNativePeerConnectionFactory() {
        return nativeGetNativePeerConnectionFactory(this.nativeFactory);
    }

    public long getNativeOwnedFactoryAndThreads() {
        return this.nativeFactory;
    }

    private static void printStackTrace(@Nullable Thread thread, String threadName) {
        if (thread != null) {
            StackTraceElement[] stackTraces = thread.getStackTrace();
            if (stackTraces.length > 0) {
                Logging.d(TAG, threadName + " stacks trace:");
                for (StackTraceElement stackTrace : stackTraces) {
                    Logging.d(TAG, stackTrace.toString());
                }
            }
        }
    }

    public static void printStackTraces() {
        printStackTrace(networkThread, "Network thread");
        printStackTrace(workerThread, "Worker thread");
        printStackTrace(signalingThread, "Signaling thread");
    }

    private static void onNetworkThreadReady() {
        networkThread = Thread.currentThread();
        Logging.d(TAG, "onNetworkThreadReady");
    }

    private static void onWorkerThreadReady() {
        workerThread = Thread.currentThread();
        Logging.d(TAG, "onWorkerThreadReady");
    }

    private static void onSignalingThreadReady() {
        signalingThread = Thread.currentThread();
        Logging.d(TAG, "onSignalingThreadReady");
    }
}
