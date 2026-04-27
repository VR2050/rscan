package im.uwrkaxlmjj.messenger.voip;

import android.media.AudioTrack;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes2.dex */
public class AudioTrackJNI {
    private AudioTrack audioTrack;
    private byte[] buffer = new byte[1920];
    private int bufferSize;
    private long nativeInst;
    private boolean needResampling;
    private boolean running;
    private Thread thread;

    /* JADX INFO: Access modifiers changed from: private */
    public native void nativeCallback(byte[] bArr);

    public AudioTrackJNI(long nativeInst) {
        this.nativeInst = nativeInst;
    }

    private int getBufferSize(int min, int sampleRate) {
        return Math.max(AudioTrack.getMinBufferSize(sampleRate, 4, 2), min);
    }

    public void init(int sampleRate, int bitsPerSample, int channels, int bufferSize) {
        if (this.audioTrack == null) {
            int size = getBufferSize(bufferSize, 48000);
            this.bufferSize = bufferSize;
            AudioTrack audioTrack = new AudioTrack(0, 48000, channels == 1 ? 4 : 12, 2, size, 1);
            this.audioTrack = audioTrack;
            if (audioTrack.getState() != 1) {
                VLog.w("Error initializing AudioTrack with 48k, trying 44.1k with resampling");
                try {
                    this.audioTrack.release();
                } catch (Throwable th) {
                }
                int size2 = getBufferSize(bufferSize * 6, 44100);
                VLog.d("buffer size: " + size2);
                this.audioTrack = new AudioTrack(0, 44100, channels == 1 ? 4 : 12, 2, size2, 1);
                this.needResampling = true;
                return;
            }
            return;
        }
        throw new IllegalStateException("already inited");
    }

    public void stop() {
        AudioTrack audioTrack = this.audioTrack;
        if (audioTrack != null) {
            try {
                audioTrack.stop();
            } catch (Exception e) {
            }
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
        AudioTrack audioTrack = this.audioTrack;
        if (audioTrack != null) {
            audioTrack.release();
            this.audioTrack = null;
        }
    }

    public void start() {
        if (this.thread == null) {
            startThread();
        } else {
            this.audioTrack.play();
        }
    }

    private void startThread() {
        if (this.thread != null) {
            throw new IllegalStateException("thread already started");
        }
        this.running = true;
        Thread thread = new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.voip.AudioTrackJNI.1
            @Override // java.lang.Runnable
            public void run() {
                try {
                    AudioTrackJNI.this.audioTrack.play();
                    ByteBuffer tmp48 = AudioTrackJNI.this.needResampling ? ByteBuffer.allocateDirect(1920) : null;
                    ByteBuffer tmp44 = AudioTrackJNI.this.needResampling ? ByteBuffer.allocateDirect(1764) : null;
                    while (AudioTrackJNI.this.running) {
                        try {
                            if (AudioTrackJNI.this.needResampling) {
                                AudioTrackJNI.this.nativeCallback(AudioTrackJNI.this.buffer);
                                tmp48.rewind();
                                tmp48.put(AudioTrackJNI.this.buffer);
                                Resampler.convert48to44(tmp48, tmp44);
                                tmp44.rewind();
                                tmp44.get(AudioTrackJNI.this.buffer, 0, 1764);
                                AudioTrackJNI.this.audioTrack.write(AudioTrackJNI.this.buffer, 0, 1764);
                            } else {
                                AudioTrackJNI.this.nativeCallback(AudioTrackJNI.this.buffer);
                                AudioTrackJNI.this.audioTrack.write(AudioTrackJNI.this.buffer, 0, 1920);
                            }
                            if (!AudioTrackJNI.this.running) {
                                AudioTrackJNI.this.audioTrack.stop();
                                break;
                            }
                            continue;
                        } catch (Exception e) {
                            VLog.e(e);
                        }
                    }
                    VLog.i("audiotrack thread exits");
                } catch (Exception x) {
                    VLog.e("error starting AudioTrack", x);
                }
            }
        });
        this.thread = thread;
        thread.start();
    }
}
