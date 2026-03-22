package tv.danmaku.ijk.media.exo.demo.player;

import android.media.MediaCodec;
import android.os.Handler;
import android.os.Looper;
import android.view.Surface;
import com.google.android.exoplayer.CodecCounters;
import com.google.android.exoplayer.DummyTrackRenderer;
import com.google.android.exoplayer.ExoPlaybackException;
import com.google.android.exoplayer.ExoPlayer;
import com.google.android.exoplayer.MediaCodecAudioTrackRenderer;
import com.google.android.exoplayer.MediaCodecTrackRenderer;
import com.google.android.exoplayer.MediaCodecVideoTrackRenderer;
import com.google.android.exoplayer.MediaFormat;
import com.google.android.exoplayer.SingleSampleSource;
import com.google.android.exoplayer.TimeRange;
import com.google.android.exoplayer.TrackRenderer;
import com.google.android.exoplayer.audio.AudioTrack;
import com.google.android.exoplayer.chunk.ChunkSampleSource;
import com.google.android.exoplayer.chunk.Format;
import com.google.android.exoplayer.dash.DashChunkSource;
import com.google.android.exoplayer.drm.StreamingDrmSessionManager;
import com.google.android.exoplayer.extractor.ExtractorSampleSource;
import com.google.android.exoplayer.hls.HlsSampleSource;
import com.google.android.exoplayer.metadata.MetadataTrackRenderer;
import com.google.android.exoplayer.metadata.id3.Id3Frame;
import com.google.android.exoplayer.text.Cue;
import com.google.android.exoplayer.text.TextRenderer;
import com.google.android.exoplayer.upstream.BandwidthMeter;
import com.google.android.exoplayer.util.DebugTextViewHelper;
import com.google.android.exoplayer.util.PlayerControl;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes3.dex */
public class DemoPlayer implements ExoPlayer.Listener, ChunkSampleSource.EventListener, HlsSampleSource.EventListener, ExtractorSampleSource.EventListener, SingleSampleSource.EventListener, BandwidthMeter.EventListener, MediaCodecVideoTrackRenderer.EventListener, MediaCodecAudioTrackRenderer.EventListener, StreamingDrmSessionManager.EventListener, DashChunkSource.EventListener, TextRenderer, MetadataTrackRenderer.MetadataRenderer<List<Id3Frame>>, DebugTextViewHelper.Provider {
    private static final int RENDERER_BUILDING_STATE_BUILDING = 2;
    private static final int RENDERER_BUILDING_STATE_BUILT = 3;
    private static final int RENDERER_BUILDING_STATE_IDLE = 1;
    public static final int RENDERER_COUNT = 4;
    public static final int STATE_BUFFERING = 3;
    public static final int STATE_ENDED = 5;
    public static final int STATE_IDLE = 1;
    public static final int STATE_PREPARING = 2;
    public static final int STATE_READY = 4;
    public static final int TRACK_DEFAULT = 0;
    public static final int TRACK_DISABLED = -1;
    public static final int TYPE_AUDIO = 1;
    public static final int TYPE_METADATA = 3;
    public static final int TYPE_TEXT = 2;
    public static final int TYPE_VIDEO = 0;
    private boolean backgrounded;
    private BandwidthMeter bandwidthMeter;
    private CaptionListener captionListener;
    private CodecCounters codecCounters;
    private Id3MetadataListener id3MetadataListener;
    private InfoListener infoListener;
    private InternalErrorListener internalErrorListener;
    private boolean lastReportedPlayWhenReady;
    private int lastReportedPlaybackState;
    private final CopyOnWriteArrayList<Listener> listeners;
    private final Handler mainHandler;
    private final ExoPlayer player;
    private final PlayerControl playerControl;
    private final RendererBuilder rendererBuilder;
    private int rendererBuildingState;
    private Surface surface;
    private Format videoFormat;
    private TrackRenderer videoRenderer;
    private int videoTrackToRestore;

    public interface CaptionListener {
        void onCues(List<Cue> list);
    }

    public interface Id3MetadataListener {
        void onId3Metadata(List<Id3Frame> list);
    }

    public interface InfoListener {
        void onAudioFormatEnabled(Format format, int i2, long j2);

        void onAvailableRangeChanged(int i2, TimeRange timeRange);

        void onBandwidthSample(int i2, long j2, long j3);

        void onDecoderInitialized(String str, long j2, long j3);

        void onDroppedFrames(int i2, long j2);

        void onLoadCompleted(int i2, long j2, int i3, int i4, Format format, long j3, long j4, long j5, long j6);

        void onLoadStarted(int i2, long j2, int i3, int i4, Format format, long j3, long j4);

        void onVideoFormatEnabled(Format format, int i2, long j2);
    }

    public interface InternalErrorListener {
        void onAudioTrackInitializationError(AudioTrack.InitializationException initializationException);

        void onAudioTrackUnderrun(int i2, long j2, long j3);

        void onAudioTrackWriteError(AudioTrack.WriteException writeException);

        void onCryptoError(MediaCodec.CryptoException cryptoException);

        void onDecoderInitializationError(MediaCodecTrackRenderer.DecoderInitializationException decoderInitializationException);

        void onDrmSessionManagerError(Exception exc);

        void onLoadError(int i2, IOException iOException);

        void onRendererInitializationError(Exception exc);
    }

    public interface Listener {
        void onError(Exception exc);

        void onStateChanged(boolean z, int i2);

        void onVideoSizeChanged(int i2, int i3, int i4, float f2);
    }

    public interface RendererBuilder {
        void buildRenderers(DemoPlayer demoPlayer);

        void cancel();
    }

    public DemoPlayer(RendererBuilder rendererBuilder) {
        this.rendererBuilder = rendererBuilder;
        ExoPlayer newInstance = ExoPlayer.Factory.newInstance(4, 1000, 5000);
        this.player = newInstance;
        newInstance.addListener(this);
        this.playerControl = new PlayerControl(newInstance);
        this.mainHandler = new Handler();
        this.listeners = new CopyOnWriteArrayList<>();
        this.lastReportedPlaybackState = 1;
        this.rendererBuildingState = 1;
        newInstance.setSelectedTrack(2, -1);
    }

    private void maybeReportPlayerState() {
        boolean playWhenReady = this.player.getPlayWhenReady();
        int playbackState = getPlaybackState();
        if (this.lastReportedPlayWhenReady == playWhenReady && this.lastReportedPlaybackState == playbackState) {
            return;
        }
        Iterator<Listener> it = this.listeners.iterator();
        while (it.hasNext()) {
            it.next().onStateChanged(playWhenReady, playbackState);
        }
        this.lastReportedPlayWhenReady = playWhenReady;
        this.lastReportedPlaybackState = playbackState;
    }

    private void pushSurface(boolean z) {
        TrackRenderer trackRenderer = this.videoRenderer;
        if (trackRenderer == null) {
            return;
        }
        if (z) {
            this.player.blockingSendMessage(trackRenderer, 1, this.surface);
        } else {
            this.player.sendMessage(trackRenderer, 1, this.surface);
        }
    }

    public void addListener(Listener listener) {
        this.listeners.add(listener);
    }

    public void blockingClearSurface() {
        this.surface = null;
        pushSurface(true);
    }

    public boolean getBackgrounded() {
        return this.backgrounded;
    }

    public BandwidthMeter getBandwidthMeter() {
        return this.bandwidthMeter;
    }

    public int getBufferedPercentage() {
        return this.player.getBufferedPercentage();
    }

    public CodecCounters getCodecCounters() {
        return this.codecCounters;
    }

    public long getCurrentPosition() {
        return this.player.getCurrentPosition();
    }

    public long getDuration() {
        return this.player.getDuration();
    }

    public Format getFormat() {
        return this.videoFormat;
    }

    public Handler getMainHandler() {
        return this.mainHandler;
    }

    public boolean getPlayWhenReady() {
        return this.player.getPlayWhenReady();
    }

    public Looper getPlaybackLooper() {
        return this.player.getPlaybackLooper();
    }

    public int getPlaybackState() {
        if (this.rendererBuildingState == 2) {
            return 2;
        }
        int playbackState = this.player.getPlaybackState();
        if (this.rendererBuildingState == 3 && playbackState == 1) {
            return 2;
        }
        return playbackState;
    }

    public PlayerControl getPlayerControl() {
        return this.playerControl;
    }

    public int getSelectedTrack(int i2) {
        return this.player.getSelectedTrack(i2);
    }

    public Surface getSurface() {
        return this.surface;
    }

    public int getTrackCount(int i2) {
        return this.player.getTrackCount(i2);
    }

    public MediaFormat getTrackFormat(int i2, int i3) {
        return this.player.getTrackFormat(i2, i3);
    }

    public void onAudioTrackInitializationError(AudioTrack.InitializationException initializationException) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onAudioTrackInitializationError(initializationException);
        }
    }

    public void onAudioTrackUnderrun(int i2, long j2, long j3) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onAudioTrackUnderrun(i2, j2, j3);
        }
    }

    public void onAudioTrackWriteError(AudioTrack.WriteException writeException) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onAudioTrackWriteError(writeException);
        }
    }

    public void onAvailableRangeChanged(int i2, TimeRange timeRange) {
        InfoListener infoListener = this.infoListener;
        if (infoListener != null) {
            infoListener.onAvailableRangeChanged(i2, timeRange);
        }
    }

    public void onBandwidthSample(int i2, long j2, long j3) {
        InfoListener infoListener = this.infoListener;
        if (infoListener != null) {
            infoListener.onBandwidthSample(i2, j2, j3);
        }
    }

    public void onCryptoError(MediaCodec.CryptoException cryptoException) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onCryptoError(cryptoException);
        }
    }

    public void onCues(List<Cue> list) {
        if (this.captionListener == null || getSelectedTrack(2) == -1) {
            return;
        }
        this.captionListener.onCues(list);
    }

    public void onDecoderInitializationError(MediaCodecTrackRenderer.DecoderInitializationException decoderInitializationException) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onDecoderInitializationError(decoderInitializationException);
        }
    }

    public void onDecoderInitialized(String str, long j2, long j3) {
        InfoListener infoListener = this.infoListener;
        if (infoListener != null) {
            infoListener.onDecoderInitialized(str, j2, j3);
        }
    }

    public void onDownstreamFormatChanged(int i2, Format format, int i3, long j2) {
        InfoListener infoListener = this.infoListener;
        if (infoListener == null) {
            return;
        }
        if (i2 == 0) {
            this.videoFormat = format;
            infoListener.onVideoFormatEnabled(format, i3, j2);
        } else if (i2 == 1) {
            infoListener.onAudioFormatEnabled(format, i3, j2);
        }
    }

    public void onDrawnToSurface(Surface surface) {
    }

    public void onDrmKeysLoaded() {
    }

    public void onDrmSessionManagerError(Exception exc) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onDrmSessionManagerError(exc);
        }
    }

    public void onDroppedFrames(int i2, long j2) {
        InfoListener infoListener = this.infoListener;
        if (infoListener != null) {
            infoListener.onDroppedFrames(i2, j2);
        }
    }

    public void onLoadCanceled(int i2, long j2) {
    }

    public void onLoadCompleted(int i2, long j2, int i3, int i4, Format format, long j3, long j4, long j5, long j6) {
        InfoListener infoListener = this.infoListener;
        if (infoListener != null) {
            infoListener.onLoadCompleted(i2, j2, i3, i4, format, j3, j4, j5, j6);
        }
    }

    public void onLoadError(int i2, IOException iOException) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onLoadError(i2, iOException);
        }
    }

    public void onLoadStarted(int i2, long j2, int i3, int i4, Format format, long j3, long j4) {
        InfoListener infoListener = this.infoListener;
        if (infoListener != null) {
            infoListener.onLoadStarted(i2, j2, i3, i4, format, j3, j4);
        }
    }

    public void onPlayWhenReadyCommitted() {
    }

    public void onPlayerError(ExoPlaybackException exoPlaybackException) {
        this.rendererBuildingState = 1;
        Iterator<Listener> it = this.listeners.iterator();
        while (it.hasNext()) {
            it.next().onError(exoPlaybackException);
        }
    }

    public void onPlayerStateChanged(boolean z, int i2) {
        maybeReportPlayerState();
    }

    public void onRenderers(TrackRenderer[] trackRendererArr, BandwidthMeter bandwidthMeter) {
        CodecCounters codecCounters;
        for (int i2 = 0; i2 < 4; i2++) {
            if (trackRendererArr[i2] == null) {
                trackRendererArr[i2] = new DummyTrackRenderer();
            }
        }
        TrackRenderer trackRenderer = trackRendererArr[0];
        this.videoRenderer = trackRenderer;
        if (!(trackRenderer instanceof MediaCodecTrackRenderer)) {
            if (!(trackRendererArr[1] instanceof MediaCodecTrackRenderer)) {
                codecCounters = null;
                this.codecCounters = codecCounters;
                this.bandwidthMeter = bandwidthMeter;
                pushSurface(false);
                this.player.prepare(trackRendererArr);
                this.rendererBuildingState = 3;
            }
            trackRenderer = trackRendererArr[1];
        }
        codecCounters = ((MediaCodecTrackRenderer) trackRenderer).codecCounters;
        this.codecCounters = codecCounters;
        this.bandwidthMeter = bandwidthMeter;
        pushSurface(false);
        this.player.prepare(trackRendererArr);
        this.rendererBuildingState = 3;
    }

    public void onRenderersError(Exception exc) {
        InternalErrorListener internalErrorListener = this.internalErrorListener;
        if (internalErrorListener != null) {
            internalErrorListener.onRendererInitializationError(exc);
        }
        Iterator<Listener> it = this.listeners.iterator();
        while (it.hasNext()) {
            it.next().onError(exc);
        }
        this.rendererBuildingState = 1;
        maybeReportPlayerState();
    }

    public void onUpstreamDiscarded(int i2, long j2, long j3) {
    }

    public void onVideoSizeChanged(int i2, int i3, int i4, float f2) {
        Iterator<Listener> it = this.listeners.iterator();
        while (it.hasNext()) {
            it.next().onVideoSizeChanged(i2, i3, i4, f2);
        }
    }

    public void prepare() {
        if (this.rendererBuildingState == 3) {
            this.player.stop();
        }
        this.rendererBuilder.cancel();
        this.videoFormat = null;
        this.videoRenderer = null;
        this.rendererBuildingState = 2;
        maybeReportPlayerState();
        this.rendererBuilder.buildRenderers(this);
    }

    public void release() {
        this.rendererBuilder.cancel();
        this.rendererBuildingState = 1;
        this.surface = null;
        this.player.release();
    }

    public void removeListener(Listener listener) {
        this.listeners.remove(listener);
    }

    public void seekTo(long j2) {
        this.player.seekTo(j2);
    }

    public void setBackgrounded(boolean z) {
        if (this.backgrounded == z) {
            return;
        }
        this.backgrounded = z;
        if (!z) {
            setSelectedTrack(0, this.videoTrackToRestore);
            return;
        }
        this.videoTrackToRestore = getSelectedTrack(0);
        setSelectedTrack(0, -1);
        blockingClearSurface();
    }

    public void setCaptionListener(CaptionListener captionListener) {
        this.captionListener = captionListener;
    }

    public void setInfoListener(InfoListener infoListener) {
        this.infoListener = infoListener;
    }

    public void setInternalErrorListener(InternalErrorListener internalErrorListener) {
        this.internalErrorListener = internalErrorListener;
    }

    public void setMetadataListener(Id3MetadataListener id3MetadataListener) {
        this.id3MetadataListener = id3MetadataListener;
    }

    public void setPlayWhenReady(boolean z) {
        this.player.setPlayWhenReady(z);
    }

    public void setSelectedTrack(int i2, int i3) {
        CaptionListener captionListener;
        this.player.setSelectedTrack(i2, i3);
        if (i2 != 2 || i3 >= 0 || (captionListener = this.captionListener) == null) {
            return;
        }
        captionListener.onCues(Collections.emptyList());
    }

    public void setSurface(Surface surface) {
        this.surface = surface;
        pushSurface(false);
    }

    public void onMetadata(List<Id3Frame> list) {
        if (this.id3MetadataListener == null || getSelectedTrack(3) == -1) {
            return;
        }
        this.id3MetadataListener.onId3Metadata(list);
    }
}
