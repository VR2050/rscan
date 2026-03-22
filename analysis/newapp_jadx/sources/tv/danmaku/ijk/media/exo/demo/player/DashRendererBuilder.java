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
import com.google.android.exoplayer.dash.DashChunkSource;
import com.google.android.exoplayer.dash.DefaultDashTrackSelector;
import com.google.android.exoplayer.dash.mpd.AdaptationSet;
import com.google.android.exoplayer.dash.mpd.MediaPresentationDescription;
import com.google.android.exoplayer.dash.mpd.MediaPresentationDescriptionParser;
import com.google.android.exoplayer.dash.mpd.Period;
import com.google.android.exoplayer.dash.mpd.UtcTimingElement;
import com.google.android.exoplayer.dash.mpd.UtcTimingElementResolver;
import com.google.android.exoplayer.drm.MediaDrmCallback;
import com.google.android.exoplayer.drm.StreamingDrmSessionManager;
import com.google.android.exoplayer.drm.UnsupportedDrmException;
import com.google.android.exoplayer.text.SubtitleParser;
import com.google.android.exoplayer.text.TextTrackRenderer;
import com.google.android.exoplayer.upstream.BandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultAllocator;
import com.google.android.exoplayer.upstream.DefaultBandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultUriDataSource;
import com.google.android.exoplayer.upstream.UriDataSource;
import com.google.android.exoplayer.util.ManifestFetcher;
import com.google.android.exoplayer.util.Util;
import java.io.IOException;
import java.util.HashMap;
import tv.danmaku.ijk.media.exo.demo.player.DemoPlayer;

/* loaded from: classes3.dex */
public class DashRendererBuilder implements DemoPlayer.RendererBuilder {
    private static final int AUDIO_BUFFER_SEGMENTS = 54;
    private static final int BUFFER_SEGMENT_SIZE = 65536;
    private static final int LIVE_EDGE_LATENCY_MS = 30000;
    private static final int SECURITY_LEVEL_1 = 1;
    private static final int SECURITY_LEVEL_3 = 3;
    private static final int SECURITY_LEVEL_UNKNOWN = -1;
    private static final String TAG = "DashRendererBuilder";
    private static final int TEXT_BUFFER_SEGMENTS = 2;
    private static final int VIDEO_BUFFER_SEGMENTS = 200;
    private final Context context;
    private AsyncRendererBuilder currentAsyncBuilder;
    private final MediaDrmCallback drmCallback;
    private final String url;
    private final String userAgent;

    public static final class AsyncRendererBuilder implements ManifestFetcher.ManifestCallback<MediaPresentationDescription>, UtcTimingElementResolver.UtcTimingCallback {
        private boolean canceled;
        private final Context context;
        private final MediaDrmCallback drmCallback;
        private long elapsedRealtimeOffset;
        private MediaPresentationDescription manifest;
        private final UriDataSource manifestDataSource;
        private final ManifestFetcher<MediaPresentationDescription> manifestFetcher;
        private final DemoPlayer player;
        private final String userAgent;

        public AsyncRendererBuilder(Context context, String str, String str2, MediaDrmCallback mediaDrmCallback, DemoPlayer demoPlayer) {
            this.context = context;
            this.userAgent = str;
            this.drmCallback = mediaDrmCallback;
            this.player = demoPlayer;
            MediaPresentationDescriptionParser mediaPresentationDescriptionParser = new MediaPresentationDescriptionParser();
            DefaultUriDataSource defaultUriDataSource = new DefaultUriDataSource(context, str);
            this.manifestDataSource = defaultUriDataSource;
            this.manifestFetcher = new ManifestFetcher<>(str2, defaultUriDataSource, mediaPresentationDescriptionParser);
        }

        private void buildRenderers() {
            boolean z;
            Period period = this.manifest.getPeriod(0);
            Handler mainHandler = this.player.getMainHandler();
            DefaultLoadControl defaultLoadControl = new DefaultLoadControl(new DefaultAllocator(65536));
            BandwidthMeter defaultBandwidthMeter = new DefaultBandwidthMeter(mainHandler, this.player);
            boolean z2 = false;
            for (int i2 = 0; i2 < period.adaptationSets.size(); i2++) {
                AdaptationSet adaptationSet = (AdaptationSet) period.adaptationSets.get(i2);
                if (adaptationSet.type != -1) {
                    z2 |= adaptationSet.hasContentProtection();
                }
            }
            StreamingDrmSessionManager streamingDrmSessionManager = null;
            if (z2) {
                if (Util.SDK_INT < 18) {
                    this.player.onRenderersError(new UnsupportedDrmException(1));
                    return;
                }
                try {
                    streamingDrmSessionManager = StreamingDrmSessionManager.newWidevineInstance(this.player.getPlaybackLooper(), this.drmCallback, (HashMap) null, this.player.getMainHandler(), this.player);
                    if (getWidevineSecurityLevel(streamingDrmSessionManager) != 1) {
                        z = true;
                        TrackRenderer mediaCodecVideoTrackRenderer = new MediaCodecVideoTrackRenderer(this.context, new ChunkSampleSource(new DashChunkSource(this.manifestFetcher, DefaultDashTrackSelector.newVideoInstance(this.context, true, z), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), new FormatEvaluator.AdaptiveEvaluator(defaultBandwidthMeter), WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, this.elapsedRealtimeOffset, mainHandler, this.player, 0), defaultLoadControl, 13107200, mainHandler, this.player, 0), MediaCodecSelector.DEFAULT, 1, 5000L, streamingDrmSessionManager, true, mainHandler, this.player, 50);
                        StreamingDrmSessionManager streamingDrmSessionManager2 = streamingDrmSessionManager;
                        TrackRenderer mediaCodecAudioTrackRenderer = new MediaCodecAudioTrackRenderer(new ChunkSampleSource(new DashChunkSource(this.manifestFetcher, DefaultDashTrackSelector.newAudioInstance(), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), (FormatEvaluator) null, WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, this.elapsedRealtimeOffset, mainHandler, this.player, 1), defaultLoadControl, 3538944, mainHandler, this.player, 1), MediaCodecSelector.DEFAULT, streamingDrmSessionManager2, true, mainHandler, this.player, AudioCapabilities.getCapabilities(this.context), 3);
                        TrackRenderer textTrackRenderer = new TextTrackRenderer(new ChunkSampleSource(new DashChunkSource(this.manifestFetcher, DefaultDashTrackSelector.newTextInstance(), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), (FormatEvaluator) null, WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, this.elapsedRealtimeOffset, mainHandler, this.player, 2), defaultLoadControl, 131072, mainHandler, this.player, 2), this.player, mainHandler.getLooper(), new SubtitleParser[0]);
                        TrackRenderer[] trackRendererArr = new TrackRenderer[4];
                        trackRendererArr[0] = mediaCodecVideoTrackRenderer;
                        trackRendererArr[1] = mediaCodecAudioTrackRenderer;
                        trackRendererArr[2] = textTrackRenderer;
                        this.player.onRenderers(trackRendererArr, defaultBandwidthMeter);
                    }
                } catch (UnsupportedDrmException e2) {
                    this.player.onRenderersError(e2);
                    return;
                }
            }
            z = false;
            TrackRenderer mediaCodecVideoTrackRenderer2 = new MediaCodecVideoTrackRenderer(this.context, new ChunkSampleSource(new DashChunkSource(this.manifestFetcher, DefaultDashTrackSelector.newVideoInstance(this.context, true, z), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), new FormatEvaluator.AdaptiveEvaluator(defaultBandwidthMeter), WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, this.elapsedRealtimeOffset, mainHandler, this.player, 0), defaultLoadControl, 13107200, mainHandler, this.player, 0), MediaCodecSelector.DEFAULT, 1, 5000L, streamingDrmSessionManager, true, mainHandler, this.player, 50);
            StreamingDrmSessionManager streamingDrmSessionManager22 = streamingDrmSessionManager;
            TrackRenderer mediaCodecAudioTrackRenderer2 = new MediaCodecAudioTrackRenderer(new ChunkSampleSource(new DashChunkSource(this.manifestFetcher, DefaultDashTrackSelector.newAudioInstance(), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), (FormatEvaluator) null, WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, this.elapsedRealtimeOffset, mainHandler, this.player, 1), defaultLoadControl, 3538944, mainHandler, this.player, 1), MediaCodecSelector.DEFAULT, streamingDrmSessionManager22, true, mainHandler, this.player, AudioCapabilities.getCapabilities(this.context), 3);
            TrackRenderer textTrackRenderer2 = new TextTrackRenderer(new ChunkSampleSource(new DashChunkSource(this.manifestFetcher, DefaultDashTrackSelector.newTextInstance(), new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), (FormatEvaluator) null, WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, this.elapsedRealtimeOffset, mainHandler, this.player, 2), defaultLoadControl, 131072, mainHandler, this.player, 2), this.player, mainHandler.getLooper(), new SubtitleParser[0]);
            TrackRenderer[] trackRendererArr2 = new TrackRenderer[4];
            trackRendererArr2[0] = mediaCodecVideoTrackRenderer2;
            trackRendererArr2[1] = mediaCodecAudioTrackRenderer2;
            trackRendererArr2[2] = textTrackRenderer2;
            this.player.onRenderers(trackRendererArr2, defaultBandwidthMeter);
        }

        private static int getWidevineSecurityLevel(StreamingDrmSessionManager streamingDrmSessionManager) {
            String propertyString = streamingDrmSessionManager.getPropertyString("securityLevel");
            if (propertyString.equals("L1")) {
                return 1;
            }
            return propertyString.equals("L3") ? 3 : -1;
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

        public void onTimestampError(UtcTimingElement utcTimingElement, IOException iOException) {
            if (this.canceled) {
                return;
            }
            String str = "Failed to resolve UtcTiming element [" + utcTimingElement + "]";
            buildRenderers();
        }

        public void onTimestampResolved(UtcTimingElement utcTimingElement, long j2) {
            if (this.canceled) {
                return;
            }
            this.elapsedRealtimeOffset = j2;
            buildRenderers();
        }

        public void onSingleManifest(MediaPresentationDescription mediaPresentationDescription) {
            if (this.canceled) {
                return;
            }
            this.manifest = mediaPresentationDescription;
            if (!mediaPresentationDescription.dynamic || mediaPresentationDescription.utcTiming == null) {
                buildRenderers();
            } else {
                UtcTimingElementResolver.resolveTimingElement(this.manifestDataSource, mediaPresentationDescription.utcTiming, this.manifestFetcher.getManifestLoadCompleteTimestamp(), this);
            }
        }
    }

    public DashRendererBuilder(Context context, String str, String str2, MediaDrmCallback mediaDrmCallback) {
        this.context = context;
        this.userAgent = str;
        this.url = str2;
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
