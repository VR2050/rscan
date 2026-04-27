package im.uwrkaxlmjj.messenger.voip;

import android.media.AudioRecord;
import android.media.audiofx.AcousticEchoCanceler;
import android.media.audiofx.AudioEffect;
import android.media.audiofx.AutomaticGainControl;
import android.media.audiofx.NoiseSuppressor;
import android.os.Build;
import android.text.TextUtils;
import java.nio.ByteBuffer;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes2.dex */
public class AudioRecordJNI {
    private AcousticEchoCanceler aec;
    private AutomaticGainControl agc;
    private AudioRecord audioRecord;
    private ByteBuffer buffer;
    private int bufferSize;
    private long nativeInst;
    private boolean needResampling = false;
    private NoiseSuppressor ns;
    private boolean running;
    private Thread thread;

    /* JADX INFO: Access modifiers changed from: private */
    public native void nativeCallback(ByteBuffer byteBuffer);

    public AudioRecordJNI(long nativeInst) {
        this.nativeInst = nativeInst;
    }

    private int getBufferSize(int min, int sampleRate) {
        return Math.max(AudioRecord.getMinBufferSize(sampleRate, 16, 2), min);
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:25:0x004d -> B:60:0x0052). Please report as a decompilation issue!!! */
    public void init(int sampleRate, int bitsPerSample, int channels, int bufferSize) {
        if (this.audioRecord != null) {
            throw new IllegalStateException("already inited");
        }
        this.bufferSize = bufferSize;
        boolean res = tryInit(7, 48000);
        boolean z = true;
        if (!res) {
            res = tryInit(1, 48000);
        }
        if (!res) {
            res = tryInit(7, 44100);
        }
        if (!res) {
            res = tryInit(1, 44100);
        }
        if (!res) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 16) {
            try {
                if (AutomaticGainControl.isAvailable()) {
                    AutomaticGainControl automaticGainControlCreate = AutomaticGainControl.create(this.audioRecord.getAudioSessionId());
                    this.agc = automaticGainControlCreate;
                    if (automaticGainControlCreate != null) {
                        automaticGainControlCreate.setEnabled(false);
                    }
                } else {
                    VLog.w("AutomaticGainControl is not available on this device :(");
                }
            } catch (Throwable x) {
                VLog.e("error creating AutomaticGainControl", x);
            }
            try {
                if (NoiseSuppressor.isAvailable()) {
                    NoiseSuppressor noiseSuppressorCreate = NoiseSuppressor.create(this.audioRecord.getAudioSessionId());
                    this.ns = noiseSuppressorCreate;
                    if (noiseSuppressorCreate != null) {
                        noiseSuppressorCreate.setEnabled(VoIPServerConfig.getBoolean("use_system_ns", true) && isGoodAudioEffect(this.ns));
                    }
                } else {
                    VLog.w("NoiseSuppressor is not available on this device :(");
                }
            } catch (Throwable x2) {
                VLog.e("error creating NoiseSuppressor", x2);
            }
            try {
                if (AcousticEchoCanceler.isAvailable()) {
                    AcousticEchoCanceler acousticEchoCancelerCreate = AcousticEchoCanceler.create(this.audioRecord.getAudioSessionId());
                    this.aec = acousticEchoCancelerCreate;
                    if (acousticEchoCancelerCreate != null) {
                        if (!VoIPServerConfig.getBoolean("use_system_aec", true) || !isGoodAudioEffect(this.aec)) {
                            z = false;
                        }
                        acousticEchoCancelerCreate.setEnabled(z);
                    }
                } else {
                    VLog.w("AcousticEchoCanceler is not available on this device");
                }
            } catch (Throwable x3) {
                VLog.e("error creating AcousticEchoCanceler", x3);
            }
        }
        this.buffer = ByteBuffer.allocateDirect(bufferSize);
    }

    private boolean tryInit(int source, int sampleRate) {
        AudioRecord audioRecord = this.audioRecord;
        if (audioRecord != null) {
            try {
                audioRecord.release();
            } catch (Exception e) {
            }
        }
        VLog.i("Trying to initialize AudioRecord with source=" + source + " and sample rate=" + sampleRate);
        int size = getBufferSize(this.bufferSize, 48000);
        try {
            this.audioRecord = new AudioRecord(source, sampleRate, 16, 2, size);
        } catch (Exception x) {
            VLog.e("AudioRecord init failed!", x);
        }
        this.needResampling = sampleRate != 48000;
        AudioRecord audioRecord2 = this.audioRecord;
        return audioRecord2 != null && audioRecord2.getState() == 1;
    }

    public void stop() {
        try {
            if (this.audioRecord != null) {
                this.audioRecord.stop();
            }
        } catch (Exception e) {
        }
    }

    public void release() {
        this.running = false;
        Thread thread = this.thread;
        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                VLog.e(e);
            }
            this.thread = null;
        }
        AudioRecord audioRecord = this.audioRecord;
        if (audioRecord != null) {
            audioRecord.release();
            this.audioRecord = null;
        }
        AutomaticGainControl automaticGainControl = this.agc;
        if (automaticGainControl != null) {
            automaticGainControl.release();
            this.agc = null;
        }
        NoiseSuppressor noiseSuppressor = this.ns;
        if (noiseSuppressor != null) {
            noiseSuppressor.release();
            this.ns = null;
        }
        AcousticEchoCanceler acousticEchoCanceler = this.aec;
        if (acousticEchoCanceler != null) {
            acousticEchoCanceler.release();
            this.aec = null;
        }
    }

    public boolean start() {
        AudioRecord audioRecord = this.audioRecord;
        if (audioRecord == null || audioRecord.getState() != 1) {
            return false;
        }
        try {
            if (this.thread == null) {
                if (this.audioRecord == null) {
                    return false;
                }
                this.audioRecord.startRecording();
                startThread();
            } else {
                this.audioRecord.startRecording();
            }
            return true;
        } catch (Exception x) {
            VLog.e("Error initializing AudioRecord", x);
            return false;
        }
    }

    private void startThread() {
        if (this.thread != null) {
            throw new IllegalStateException("thread already started");
        }
        this.running = true;
        final ByteBuffer tmpBuf = this.needResampling ? ByteBuffer.allocateDirect(1764) : null;
        Thread thread = new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.voip.AudioRecordJNI.1
            @Override // java.lang.Runnable
            public void run() {
                while (AudioRecordJNI.this.running) {
                    try {
                        if (!AudioRecordJNI.this.needResampling) {
                            AudioRecordJNI.this.audioRecord.read(AudioRecordJNI.this.buffer, 1920);
                        } else {
                            AudioRecordJNI.this.audioRecord.read(tmpBuf, 1764);
                            Resampler.convert44to48(tmpBuf, AudioRecordJNI.this.buffer);
                        }
                        if (!AudioRecordJNI.this.running) {
                            AudioRecordJNI.this.audioRecord.stop();
                            break;
                        }
                        AudioRecordJNI.this.nativeCallback(AudioRecordJNI.this.buffer);
                    } catch (Exception e) {
                        VLog.e(e);
                    }
                }
                VLog.i("audiorecord thread exits");
            }
        });
        this.thread = thread;
        thread.start();
    }

    public int getEnabledEffectsMask() {
        int r = 0;
        AcousticEchoCanceler acousticEchoCanceler = this.aec;
        if (acousticEchoCanceler != null && acousticEchoCanceler.getEnabled()) {
            r = 0 | 1;
        }
        NoiseSuppressor noiseSuppressor = this.ns;
        if (noiseSuppressor != null && noiseSuppressor.getEnabled()) {
            return r | 2;
        }
        return r;
    }

    private static Pattern makeNonEmptyRegex(String configKey) {
        String r = VoIPServerConfig.getString(configKey, "");
        if (TextUtils.isEmpty(r)) {
            return null;
        }
        try {
            return Pattern.compile(r);
        } catch (Exception x) {
            VLog.e(x);
            return null;
        }
    }

    private static boolean isGoodAudioEffect(AudioEffect effect) {
        Pattern globalImpl = makeNonEmptyRegex("adsp_good_impls");
        Pattern globalName = makeNonEmptyRegex("adsp_good_names");
        AudioEffect.Descriptor desc = effect.getDescriptor();
        VLog.d(effect.getClass().getSimpleName() + ": implementor=" + desc.implementor + ", name=" + desc.name);
        if (globalImpl != null && globalImpl.matcher(desc.implementor).find()) {
            return true;
        }
        if (globalName != null && globalName.matcher(desc.name).find()) {
            return true;
        }
        if (effect instanceof AcousticEchoCanceler) {
            Pattern impl = makeNonEmptyRegex("aaec_good_impls");
            Pattern name = makeNonEmptyRegex("aaec_good_names");
            if (impl != null && impl.matcher(desc.implementor).find()) {
                return true;
            }
            if (name != null && name.matcher(desc.name).find()) {
                return true;
            }
        }
        if (effect instanceof NoiseSuppressor) {
            Pattern impl2 = makeNonEmptyRegex("ans_good_impls");
            Pattern name2 = makeNonEmptyRegex("ans_good_names");
            if (impl2 != null && impl2.matcher(desc.implementor).find()) {
                return true;
            }
            if (name2 != null && name2.matcher(desc.name).find()) {
                return true;
            }
            return false;
        }
        return false;
    }
}
