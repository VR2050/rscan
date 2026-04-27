package org.webrtc.mozi;

import android.content.Context;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioPlaybackCaptureConfiguration;
import android.media.AudioRecord;
import android.media.projection.MediaProjection;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

/* JADX INFO: loaded from: classes3.dex */
public class ScreenAudioCapturer {
    private static final int BUFFERS_PER_SECOND = 100;
    private static final int BUFFER_SIZE_FACTOR = 2;
    private static final int BYTES_PER_SAMPLE = 2;
    private static final int CALLBACK_BUFFER_SIZE_MS = 10;
    private static final boolean DEBUG = false;
    public static final int ERROR_AUDIO_RECORD_INIT_EXCEPTION = -102;
    public static final int ERROR_AUDIO_RECORD_INIT_STATE_MISMATCH = -103;
    public static final int ERROR_AUDIO_RECORD_INVALID_OPERATION = -106;
    public static final int ERROR_AUDIO_RECORD_START_EXCEPTION = -104;
    public static final int ERROR_AUDIO_RECORD_START_STATE_MISMATCH = -105;
    public static final int ERROR_NO_MEDIA_PROJECTION = -107;
    public static final int ERROR_SCREEN_CAPTURE_PERMISSION_DENIED = -1000;
    public static final int ERROR_SCREEN_CAPTURE_SYSTEM_AUDIO_NOT_SUPPORTED = -1002;
    public static final int ERROR_SCREEN_CAPTURE_SYSTEM_NOT_SUPPORTED = -1001;
    public static final int ERROR_UNKNOWN = -1;
    private static final int RECORDER_AUDIO_ENCODING = 2;
    private static final String TAG = "ScreenAudioCapturer";
    private AudioManager mAudioManager;
    private int mAudioModeWhenStart = -2;
    private AudioRecordThread mAudioThread;
    private byte[] mBuffer;
    private int mBufferSize;
    private Context mContext;
    private ScreenAudioCapturerObserver mObserver;

    public interface ScreenAudioCapturerObserver {
        void OnAudioCaptured(byte[] bArr, int i, int i2, int i3);

        void onError(int i);

        void onStarted();

        void onStopped();
    }

    public void setScreenAudioCapturerObserver(ScreenAudioCapturerObserver observer) {
        this.mObserver = observer;
    }

    private class AudioRecordThread extends Thread {
        private AudioRecord mAudioRecord;
        private int mChannels;
        private volatile boolean mKeepAlive;
        private MediaProjection mMediaProjection;
        private int mSampleRate;

        public AudioRecordThread(String name, MediaProjection mediaProjection, int sampleRate, int channels) {
            super(name);
            this.mKeepAlive = true;
            this.mMediaProjection = mediaProjection;
            this.mSampleRate = sampleRate;
            this.mChannels = channels;
        }

        private int init(MediaProjection mediaProjection, int sampleRate, int channels) {
            if (mediaProjection != null) {
                int channelMask = ScreenAudioCapturer.this.channelCountToConfiguration(channels);
                AudioPlaybackCaptureConfiguration config = new AudioPlaybackCaptureConfiguration.Builder(mediaProjection).addMatchingUsage(1).addMatchingUsage(0).addMatchingUsage(14).build();
                AudioFormat audioFormat = new AudioFormat.Builder().setEncoding(2).setSampleRate(sampleRate).setChannelMask(channelMask).build();
                int minBufferSize = AudioRecord.getMinBufferSize(sampleRate, channelMask, 2) * 2;
                try {
                    AudioRecord audioRecordBuild = new AudioRecord.Builder().setAudioFormat(audioFormat).setBufferSizeInBytes(Math.max(minBufferSize, ScreenAudioCapturer.this.mBufferSize)).setAudioPlaybackCaptureConfig(config).build();
                    this.mAudioRecord = audioRecordBuild;
                    if (audioRecordBuild.getState() != 1) {
                        releaseAudioResources();
                        return ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_STATE_MISMATCH;
                    }
                    logMainParameters();
                    return 0;
                } catch (Exception e) {
                    Logging.e(ScreenAudioCapturer.TAG, "AudioRecord build Exception:" + Log.getStackTraceString(e));
                    releaseAudioResources();
                    return ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_EXCEPTION;
                }
            }
            Logging.e(ScreenAudioCapturer.TAG, "mediaProjection is null");
            return ScreenAudioCapturer.ERROR_NO_MEDIA_PROJECTION;
        }

        private int startRecording() {
            try {
                this.mAudioRecord.startRecording();
                if (this.mAudioRecord.getRecordingState() != 3) {
                    return ScreenAudioCapturer.ERROR_AUDIO_RECORD_START_STATE_MISMATCH;
                }
                return 0;
            } catch (IllegalStateException e) {
                Logging.e(ScreenAudioCapturer.TAG, "AudioRecord.startRecording failed: " + e.getMessage());
                return ScreenAudioCapturer.ERROR_AUDIO_RECORD_START_EXCEPTION;
            }
        }

        private void releaseAudioResources() {
            Logging.d(ScreenAudioCapturer.TAG, "releaseAudioResources");
            if (this.mAudioRecord != null) {
                long time = SystemClock.elapsedRealtime();
                this.mAudioRecord.release();
                Logging.i(ScreenAudioCapturer.TAG, "mAudioRecord.release costtime:" + (SystemClock.elapsedRealtime() - time));
                this.mAudioRecord = null;
            }
        }

        public MediaProjection getMediaProjection() {
            return this.mMediaProjection;
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            Process.setThreadPriority(-19);
            int ret = -1002;
            if (Build.VERSION.SDK_INT >= 29) {
                ret = init(this.mMediaProjection, this.mSampleRate, this.mChannels);
            }
            if (ret < 0) {
                if (ScreenAudioCapturer.this.mObserver != null) {
                    ScreenAudioCapturer.this.mObserver.onError(ret);
                    return;
                }
                return;
            }
            setAudioMode();
            int ret2 = startRecording();
            if (ret2 == 0) {
                if (ScreenAudioCapturer.this.mObserver != null) {
                    ScreenAudioCapturer.this.mObserver.onStarted();
                }
                System.nanoTime();
                int needSize = ScreenAudioCapturer.this.mBufferSize;
                while (this.mKeepAlive) {
                    int bytesRead = this.mAudioRecord.read(ScreenAudioCapturer.this.mBuffer, 0, needSize);
                    if (bytesRead == needSize) {
                        if (this.mKeepAlive && ScreenAudioCapturer.this.mObserver != null) {
                            ScreenAudioCapturer.this.mObserver.OnAudioCaptured(ScreenAudioCapturer.this.mBuffer, bytesRead, this.mSampleRate, this.mChannels);
                        }
                    } else {
                        Logging.e(ScreenAudioCapturer.TAG, "AudioRecord.read failed: " + bytesRead);
                        if (bytesRead == -3) {
                            this.mKeepAlive = false;
                            if (ScreenAudioCapturer.this.mObserver != null) {
                                ScreenAudioCapturer.this.mObserver.onError(ScreenAudioCapturer.ERROR_AUDIO_RECORD_INVALID_OPERATION);
                            }
                        }
                    }
                }
                recoverAudioMode();
                try {
                    if (this.mAudioRecord != null) {
                        Logging.i(ScreenAudioCapturer.TAG, "ScreenAudioCapturer mAudioRecord.stop start");
                        long time = SystemClock.elapsedRealtime();
                        this.mAudioRecord.stop();
                        Logging.i(ScreenAudioCapturer.TAG, "ScreenAudioCapturer mAudioRecord.stop:" + (SystemClock.elapsedRealtime() - time));
                    }
                } catch (IllegalStateException e) {
                    Logging.e(ScreenAudioCapturer.TAG, "ScreenAudioCapturer AudioRecord.stop failed: " + e.getMessage());
                }
                releaseAudioResources();
                return;
            }
            recoverAudioMode();
            if (ScreenAudioCapturer.this.mObserver != null) {
                ScreenAudioCapturer.this.mObserver.onError(ret2);
            }
        }

        private void setAudioMode() {
            ScreenAudioCapturer screenAudioCapturer = ScreenAudioCapturer.this;
            screenAudioCapturer.mAudioModeWhenStart = screenAudioCapturer.mAudioManager.getMode();
            Logging.i(ScreenAudioCapturer.TAG, "startRecording get audio mode:" + ScreenAudioCapturer.this.mAudioModeWhenStart);
            ScreenAudioCapturer.this.mAudioManager.setMode(0);
        }

        private void recoverAudioMode() {
            Logging.i(ScreenAudioCapturer.TAG, "stopRecording recover audio mode:" + ScreenAudioCapturer.this.mAudioModeWhenStart);
            if (ScreenAudioCapturer.this.mAudioModeWhenStart != -2) {
                ScreenAudioCapturer.this.mAudioManager.setMode(ScreenAudioCapturer.this.mAudioModeWhenStart);
                ScreenAudioCapturer.this.mAudioModeWhenStart = -2;
            }
        }

        public void stopThread() {
            Logging.d(ScreenAudioCapturer.TAG, "ScreenAudioCapturer stopThread");
            this.mKeepAlive = false;
        }

        private void logMainParameters() {
            StringBuilder sb = new StringBuilder();
            sb.append("AudioRecord: session ID: ");
            sb.append(this.mAudioRecord.getAudioSessionId());
            sb.append(", ");
            sb.append("channels: ");
            sb.append(this.mAudioRecord.getChannelCount());
            sb.append(", ");
            sb.append("sample rate: ");
            sb.append(this.mAudioRecord.getSampleRate());
            sb.append(", ");
            sb.append("buffer size in frames: ");
            sb.append(Build.VERSION.SDK_INT >= 23 ? Integer.valueOf(this.mAudioRecord.getBufferSizeInFrames()) : "unknown");
            Logging.d(ScreenAudioCapturer.TAG, sb.toString());
        }
    }

    public ScreenAudioCapturer(Context context) {
        this.mContext = context;
        this.mAudioManager = (AudioManager) context.getSystemService("audio");
    }

    public int startCapture(MediaProjection mediaProjection, int sampleRate, int channels) {
        Logging.d(TAG, "startCapture");
        if (this.mAudioThread != null) {
            Logging.d(TAG, "startCapture audio record thread already running");
            return 0;
        }
        int bytesPerFrame = channels * 2;
        int framesPerBuffer = sampleRate / 100;
        int i = bytesPerFrame * framesPerBuffer;
        this.mBufferSize = i;
        this.mBuffer = new byte[i];
        AudioRecordThread audioRecordThread = new AudioRecordThread("AudioRecordJavaThread", mediaProjection, sampleRate, channels);
        this.mAudioThread = audioRecordThread;
        audioRecordThread.start();
        return 0;
    }

    public MediaProjection getMediaProjection() {
        AudioRecordThread audioRecordThread = this.mAudioThread;
        if (audioRecordThread != null) {
            return audioRecordThread.getMediaProjection();
        }
        return null;
    }

    public void stopCapture() {
        Logging.d(TAG, "ScreenAudioCapturer stopCapture");
        AudioRecordThread audioRecordThread = this.mAudioThread;
        if (audioRecordThread == null) {
            return;
        }
        audioRecordThread.stopThread();
        this.mAudioThread = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int channelCountToConfiguration(int channels) {
        return channels == 1 ? 16 : 12;
    }
}
