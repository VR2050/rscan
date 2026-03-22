package tv.danmaku.ijk.media.exo.demo.player;

import android.content.Context;
import android.os.Handler;
import androidx.work.WorkRequest;
import com.google.android.exoplayer.DefaultLoadControl;
import com.google.android.exoplayer.MediaCodecAudioTrackRenderer;
import com.google.android.exoplayer.MediaCodecSelector;
import com.google.android.exoplayer.MediaCodecVideoTrackRenderer;
import com.google.android.exoplayer.TrackRenderer;
import com.google.android.exoplayer.audio.AudioCapabilities;
import com.google.android.exoplayer.chunk.ChunkSampleSource;
import com.google.android.exoplayer.chunk.FormatEvaluator;
import com.google.android.exoplayer.drm.MediaDrmCallback;
import com.google.android.exoplayer.drm.StreamingDrmSessionManager;
import com.google.android.exoplayer.drm.UnsupportedDrmException;
import com.google.android.exoplayer.smoothstreaming.DefaultSmoothStreamingTrackSelector;
import com.google.android.exoplayer.smoothstreaming.SmoothStreamingChunkSource;
import com.google.android.exoplayer.smoothstreaming.SmoothStreamingManifest;
import com.google.android.exoplayer.smoothstreaming.SmoothStreamingManifestParser;
import com.google.android.exoplayer.text.SubtitleParser;
import com.google.android.exoplayer.text.TextTrackRenderer;
import com.google.android.exoplayer.upstream.BandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultAllocator;
import com.google.android.exoplayer.upstream.DefaultBandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultHttpDataSource;
import com.google.android.exoplayer.upstream.DefaultUriDataSource;
import com.google.android.exoplayer.util.ManifestFetcher;
import com.google.android.exoplayer.util.Predicate;
import com.google.android.exoplayer.util.Util;
import java.io.IOException;
import java.util.HashMap;
import p005b.p131d.p132a.p133a.C1499a;
import tv.danmaku.ijk.media.exo.demo.player.DemoPlayer;

/* loaded from: classes3.dex */
public class SmoothStreamingRendererBuilder implements DemoPlayer.RendererBuilder {
    private static final int AUDIO_BUFFER_SEGMENTS = 54;
    private static final int BUFFER_SEGMENT_SIZE = 65536;
    private static final int LIVE_EDGE_LATENCY_MS = 30000;
    private static final int TEXT_BUFFER_SEGMENTS = 2;
    private static final int VIDEO_BUFFER_SEGMENTS = 200;
    private final Context context;
    private AsyncRendererBuilder currentAsyncBuilder;
    private final MediaDrmCallback drmCallback;
    private final String url;
    private final String userAgent;

    public static final class AsyncRendererBuilder implements ManifestFetcher.ManifestCallback<SmoothStreamingManifest> {
        private boolean canceled;
        private final Context context;
        private final MediaDrmCallback drmCallback;
        private final ManifestFetcher<SmoothStreamingManifest> manifestFetcher;
        private final DemoPlayer player;
        private final String userAgent;

        public AsyncRendererBuilder(Context context, String str, String str2, MediaDrmCallback mediaDrmCallback, DemoPlayer demoPlayer) {
            this.context = context;
            this.userAgent = str;
            this.drmCallback = mediaDrmCallback;
            this.player = demoPlayer;
            this.manifestFetcher = new ManifestFetcher<>(str2, new DefaultHttpDataSource(str, (Predicate) null), new SmoothStreamingManifestParser());
        }

        public void cancel() {
            this.canceled = true;
        }

        public void init() {
            this.manifestFetcher.singleLoad(this.player.getMainHandler().getLooper(), this);
        }

        public void onSingleManifestError(IOException iOException) {
            if (this.canceled) {
                return;
            }
            this.player.onRenderersError(iOException);
        }

        public void onSingleManifest(SmoothStreamingManifest smoothStreamingManifest) {
            StreamingDrmSessionManager streamingDrmSessionManager;
            if (this.canceled) {
                return;
            }
            Handler mainHandler = this.player.getMainHandler();
            DefaultLoadControl defaultLoadControl = new DefaultLoadControl(new DefaultAllocator(65536));
            BandwidthMeter defaultBandwidthMeter = new DefaultBandwidthMeter(mainHandler, this.player);
            if (smoothStreamingManifest.protectionElement == null) {
                streamingDrmSessionManager = null;
            } else {
                if (Util.SDK_INT < 18) {
                    this.player.onRenderersError(new UnsupportedDrmException(1));
                    return;
                }
                try {
                    streamingDrmSessionManager = StreamingDrmSessionManager.newFrameworkInstance(smoothStreamingManifest.protectionElement.uuid, this.player.getPlaybackLooper(), this.drmCallback, (HashMap) null, this.player.getMainHandler(), this.player);
                } catch (UnsupportedDrmException e2) {
                    this.player.onRenderersError(e2);
                    return;
                }
            }
            TrackRenderer mediaCodecVideoTrackRenderer = new MediaCodecVideoTrackRenderer(this.context, new ChunkSampleSource(new SmoothStreamingChunkSource(this.manifestFetcher, DefaultSmoothStreamingTrackSelector.newVideoInstance(this.context, true, false), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), new FormatEvaluator.AdaptiveEvaluator(defaultBandwidthMeter), WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS), defaultLoadControl, 13107200, mainHandler, this.player, 0), MediaCodecSelector.DEFAULT, 1, 5000L, streamingDrmSessionManager, true, mainHandler, this.player, 50);
            TrackRenderer mediaCodecAudioTrackRenderer = new MediaCodecAudioTrackRenderer(new ChunkSampleSource(new SmoothStreamingChunkSource(this.manifestFetcher, DefaultSmoothStreamingTrackSelector.newAudioInstance(), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), (FormatEvaluator) null, WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS), defaultLoadControl, 3538944, mainHandler, this.player, 1), MediaCodecSelector.DEFAULT, streamingDrmSessionManager, true, mainHandler, this.player, AudioCapabilities.getCapabilities(this.context), 3);
            TrackRenderer textTrackRenderer = new TextTrackRenderer(new ChunkSampleSource(new SmoothStreamingChunkSource(this.manifestFetcher, DefaultSmoothStreamingTrackSelector.newTextInstance(), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), (FormatEvaluator) null, WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS), defaultLoadControl, 131072, mainHandler, this.player, 2), this.player, mainHandler.getLooper(), new SubtitleParser[0]);
            TrackRenderer[] trackRendererArr = new TrackRenderer[4];
            trackRendererArr[0] = mediaCodecVideoTrackRenderer;
            trackRendererArr[1] = mediaCodecAudioTrackRenderer;
            trackRendererArr[2] = textTrackRenderer;
            this.player.onRenderers(trackRendererArr, defaultBandwidthMeter);
        }
    }

    public SmoothStreamingRendererBuilder(Context context, String str, String str2, MediaDrmCallback mediaDrmCallback) {
        this.context = context;
        this.userAgent = str;
        this.url = Util.toLowerInvariant(str2).endsWith("/manifest") ? str2 : C1499a.m637w(str2, "/Manifest");
        this.drmCallback = mediaDrmCallback;
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.RendererBuilder
    public void buildRenderers(DemoPlayer demoPlayer) {
        AsyncRendererBuilder asyncRendererBuilder = new AsyncRendererBuilder(this.context, this.userAgent, this.url, this.drmCallback, demoPlayer);
        this.currentAsyncBuilder = asyncRendererBuilder;
        asyncRendererBuilder.init();
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.RendererBuilder
    public void cancel() {
        AsyncRendererBuilder asyncRendererBuilder = this.currentAsyncBuilder;
        if (asyncRendererBuilder != null) {
            asyncRendererBuilder.cancel();
            this.currentAsyncBuilder = null;
        }
    }
}
