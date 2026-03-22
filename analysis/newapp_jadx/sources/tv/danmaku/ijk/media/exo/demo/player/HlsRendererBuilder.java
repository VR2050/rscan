package tv.danmaku.ijk.media.exo.demo.player;

import android.content.Context;
import android.os.Handler;
import com.google.android.exoplayer.DefaultLoadControl;
import com.google.android.exoplayer.MediaCodecAudioTrackRenderer;
import com.google.android.exoplayer.MediaCodecSelector;
import com.google.android.exoplayer.MediaCodecVideoTrackRenderer;
import com.google.android.exoplayer.SampleSource;
import com.google.android.exoplayer.TrackRenderer;
import com.google.android.exoplayer.audio.AudioCapabilities;
import com.google.android.exoplayer.drm.DrmSessionManager;
import com.google.android.exoplayer.hls.DefaultHlsTrackSelector;
import com.google.android.exoplayer.hls.HlsChunkSource;
import com.google.android.exoplayer.hls.HlsMasterPlaylist;
import com.google.android.exoplayer.hls.HlsPlaylist;
import com.google.android.exoplayer.hls.HlsPlaylistParser;
import com.google.android.exoplayer.hls.HlsSampleSource;
import com.google.android.exoplayer.hls.PtsTimestampAdjusterProvider;
import com.google.android.exoplayer.metadata.MetadataTrackRenderer;
import com.google.android.exoplayer.metadata.id3.Id3Parser;
import com.google.android.exoplayer.text.SubtitleParser;
import com.google.android.exoplayer.text.TextTrackRenderer;
import com.google.android.exoplayer.text.eia608.Eia608TrackRenderer;
import com.google.android.exoplayer.upstream.BandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultAllocator;
import com.google.android.exoplayer.upstream.DefaultBandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultUriDataSource;
import com.google.android.exoplayer.util.ManifestFetcher;
import java.io.IOException;
import tv.danmaku.ijk.media.exo.demo.player.DemoPlayer;

/* loaded from: classes3.dex */
public class HlsRendererBuilder implements DemoPlayer.RendererBuilder {
    private static final int AUDIO_BUFFER_SEGMENTS = 54;
    private static final int BUFFER_SEGMENT_SIZE = 65536;
    private static final int MAIN_BUFFER_SEGMENTS = 254;
    private static final int TEXT_BUFFER_SEGMENTS = 2;
    private final Context context;
    private AsyncRendererBuilder currentAsyncBuilder;
    private final String url;
    private final String userAgent;

    public static final class AsyncRendererBuilder implements ManifestFetcher.ManifestCallback<HlsPlaylist> {
        private boolean canceled;
        private final Context context;
        private final DemoPlayer player;
        private final ManifestFetcher<HlsPlaylist> playlistFetcher;
        private final String userAgent;

        public AsyncRendererBuilder(Context context, String str, String str2, DemoPlayer demoPlayer) {
            this.context = context;
            this.userAgent = str;
            this.player = demoPlayer;
            this.playlistFetcher = new ManifestFetcher<>(str2, new DefaultUriDataSource(context, str), new HlsPlaylistParser());
        }

        public void cancel() {
            this.canceled = true;
        }

        public void init() {
            this.playlistFetcher.singleLoad(this.player.getMainHandler().getLooper(), this);
        }

        public void onSingleManifestError(IOException iOException) {
            if (this.canceled) {
                return;
            }
            this.player.onRenderersError(iOException);
        }

        public void onSingleManifest(HlsPlaylist hlsPlaylist) {
            boolean z;
            boolean z2;
            BandwidthMeter bandwidthMeter;
            SampleSource sampleSource;
            TrackRenderer trackRenderer;
            MediaCodecAudioTrackRenderer mediaCodecAudioTrackRenderer;
            BandwidthMeter bandwidthMeter2;
            char c2;
            char c3;
            TextTrackRenderer eia608TrackRenderer;
            if (this.canceled) {
                return;
            }
            Handler mainHandler = this.player.getMainHandler();
            DefaultLoadControl defaultLoadControl = new DefaultLoadControl(new DefaultAllocator(65536));
            BandwidthMeter defaultBandwidthMeter = new DefaultBandwidthMeter();
            PtsTimestampAdjusterProvider ptsTimestampAdjusterProvider = new PtsTimestampAdjusterProvider();
            if (hlsPlaylist instanceof HlsMasterPlaylist) {
                HlsMasterPlaylist hlsMasterPlaylist = (HlsMasterPlaylist) hlsPlaylist;
                boolean z3 = !hlsMasterPlaylist.subtitles.isEmpty();
                z = !hlsMasterPlaylist.audios.isEmpty();
                z2 = z3;
            } else {
                z = false;
                z2 = false;
            }
            SampleSource hlsSampleSource = new HlsSampleSource(new HlsChunkSource(true, new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), hlsPlaylist, DefaultHlsTrackSelector.newDefaultInstance(this.context), defaultBandwidthMeter, ptsTimestampAdjusterProvider), defaultLoadControl, 16646144, mainHandler, this.player, 0);
            TrackRenderer mediaCodecVideoTrackRenderer = new MediaCodecVideoTrackRenderer(this.context, hlsSampleSource, MediaCodecSelector.DEFAULT, 1, 5000L, mainHandler, this.player, 50);
            TrackRenderer metadataTrackRenderer = new MetadataTrackRenderer(hlsSampleSource, new Id3Parser(), this.player, mainHandler.getLooper());
            if (z) {
                bandwidthMeter = defaultBandwidthMeter;
                sampleSource = hlsSampleSource;
                trackRenderer = metadataTrackRenderer;
                mediaCodecAudioTrackRenderer = new MediaCodecAudioTrackRenderer(new SampleSource[]{sampleSource, new HlsSampleSource(new HlsChunkSource(false, new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), hlsPlaylist, DefaultHlsTrackSelector.newAudioInstance(), bandwidthMeter, ptsTimestampAdjusterProvider), defaultLoadControl, 3538944, mainHandler, this.player, 1)}, MediaCodecSelector.DEFAULT, (DrmSessionManager) null, true, this.player.getMainHandler(), this.player, AudioCapabilities.getCapabilities(this.context), 3);
            } else {
                bandwidthMeter = defaultBandwidthMeter;
                sampleSource = hlsSampleSource;
                trackRenderer = metadataTrackRenderer;
                mediaCodecAudioTrackRenderer = new MediaCodecAudioTrackRenderer(sampleSource, MediaCodecSelector.DEFAULT, (DrmSessionManager) null, true, this.player.getMainHandler(), this.player, AudioCapabilities.getCapabilities(this.context), 3);
            }
            MediaCodecAudioTrackRenderer mediaCodecAudioTrackRenderer2 = mediaCodecAudioTrackRenderer;
            if (z2) {
                c2 = 2;
                bandwidthMeter2 = bandwidthMeter;
                c3 = 0;
                eia608TrackRenderer = new TextTrackRenderer(new HlsSampleSource(new HlsChunkSource(false, new DefaultUriDataSource(this.context, bandwidthMeter, this.userAgent), hlsPlaylist, DefaultHlsTrackSelector.newSubtitleInstance(), bandwidthMeter, ptsTimestampAdjusterProvider), defaultLoadControl, 131072, mainHandler, this.player, 2), this.player, mainHandler.getLooper(), new SubtitleParser[0]);
            } else {
                bandwidthMeter2 = bandwidthMeter;
                c2 = 2;
                c3 = 0;
                eia608TrackRenderer = new Eia608TrackRenderer(sampleSource, this.player, mainHandler.getLooper());
            }
            TrackRenderer[] trackRendererArr = new TrackRenderer[4];
            trackRendererArr[c3] = mediaCodecVideoTrackRenderer;
            trackRendererArr[1] = mediaCodecAudioTrackRenderer2;
            trackRendererArr[3] = trackRenderer;
            trackRendererArr[c2] = eia608TrackRenderer;
            this.player.onRenderers(trackRendererArr, bandwidthMeter2);
        }
    }

    public HlsRendererBuilder(Context context, String str, String str2) {
        this.context = context;
        this.userAgent = str;
        this.url = str2;
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.RendererBuilder
    public void buildRenderers(DemoPlayer demoPlayer) {
        AsyncRendererBuilder asyncRendererBuilder = new AsyncRendererBuilder(this.context, this.userAgent, this.url, demoPlayer);
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
