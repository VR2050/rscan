package tv.danmaku.ijk.media.exo.demo;

import android.media.MediaCodec;
import android.os.SystemClock;
import androidx.exifinterface.media.ExifInterface;
import com.google.android.exoplayer.MediaCodecTrackRenderer;
import com.google.android.exoplayer.TimeRange;
import com.google.android.exoplayer.audio.AudioTrack;
import com.google.android.exoplayer.chunk.Format;
import com.google.android.exoplayer.util.VerboseLogUtil;
import java.io.IOException;
import java.text.NumberFormat;
import java.util.Locale;
import tv.danmaku.ijk.media.exo.demo.player.DemoPlayer;

/* loaded from: classes3.dex */
public class EventLogger implements DemoPlayer.Listener, DemoPlayer.InfoListener, DemoPlayer.InternalErrorListener {
    private static final String TAG = "EventLogger";
    private static final NumberFormat TIME_FORMAT;
    private long[] availableRangeValuesUs;
    private long[] loadStartTimeMs = new long[4];
    private long sessionStartTimeMs;

    static {
        NumberFormat numberFormat = NumberFormat.getInstance(Locale.US);
        TIME_FORMAT = numberFormat;
        numberFormat.setMinimumFractionDigits(2);
        numberFormat.setMaximumFractionDigits(2);
    }

    private String getSessionTimeString() {
        return getTimeString(SystemClock.elapsedRealtime() - this.sessionStartTimeMs);
    }

    private String getStateString(int i2) {
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? i2 != 4 ? i2 != 5 ? "?" : ExifInterface.LONGITUDE_EAST : "R" : "B" : "P" : "I";
    }

    private String getTimeString(long j2) {
        return TIME_FORMAT.format(j2 / 1000.0f);
    }

    private void printInternalError(String str, Exception exc) {
        getSessionTimeString();
    }

    public void endSession() {
        getSessionTimeString();
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onAudioFormatEnabled(Format format, int i2, long j2) {
        getSessionTimeString();
        String str = format.id;
        Integer.toString(i2);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onAudioTrackInitializationError(AudioTrack.InitializationException initializationException) {
        printInternalError("audioTrackInitializationError", initializationException);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onAudioTrackUnderrun(int i2, long j2, long j3) {
        printInternalError("audioTrackUnderrun [" + i2 + ", " + j2 + ", " + j3 + "]", null);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onAudioTrackWriteError(AudioTrack.WriteException writeException) {
        printInternalError("audioTrackWriteError", writeException);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onAvailableRangeChanged(int i2, TimeRange timeRange) {
        this.availableRangeValuesUs = timeRange.getCurrentBoundsUs(this.availableRangeValuesUs);
        timeRange.isStatic();
        long[] jArr = this.availableRangeValuesUs;
        long j2 = jArr[0];
        long j3 = jArr[1];
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onBandwidthSample(int i2, long j2, long j3) {
        getSessionTimeString();
        getTimeString(i2);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onCryptoError(MediaCodec.CryptoException cryptoException) {
        printInternalError("cryptoError", cryptoException);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onDecoderInitializationError(MediaCodecTrackRenderer.DecoderInitializationException decoderInitializationException) {
        printInternalError("decoderInitializationError", decoderInitializationException);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onDecoderInitialized(String str, long j2, long j3) {
        getSessionTimeString();
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onDrmSessionManagerError(Exception exc) {
        printInternalError("drmSessionManagerError", exc);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onDroppedFrames(int i2, long j2) {
        getSessionTimeString();
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.Listener
    public void onError(Exception exc) {
        getSessionTimeString();
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onLoadCompleted(int i2, long j2, int i3, int i4, Format format, long j3, long j4, long j5, long j6) {
        if (VerboseLogUtil.isTagEnabled(TAG)) {
            SystemClock.elapsedRealtime();
            long j7 = this.loadStartTimeMs[i2];
            getSessionTimeString();
        }
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onLoadError(int i2, IOException iOException) {
        printInternalError("loadError", iOException);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onLoadStarted(int i2, long j2, int i3, int i4, Format format, long j3, long j4) {
        this.loadStartTimeMs[i2] = SystemClock.elapsedRealtime();
        if (VerboseLogUtil.isTagEnabled(TAG)) {
            getSessionTimeString();
        }
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InternalErrorListener
    public void onRendererInitializationError(Exception exc) {
        printInternalError("rendererInitError", exc);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.Listener
    public void onStateChanged(boolean z, int i2) {
        getSessionTimeString();
        getStateString(i2);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.InfoListener
    public void onVideoFormatEnabled(Format format, int i2, long j2) {
        getSessionTimeString();
        String str = format.id;
        Integer.toString(i2);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.Listener
    public void onVideoSizeChanged(int i2, int i3, int i4, float f2) {
    }

    public void startSession() {
        this.sessionStartTimeMs = SystemClock.elapsedRealtime();
    }
}
