package tv.danmaku.ijk.media.exo.demo.player;

import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import com.google.android.exoplayer.MediaCodecAudioTrackRenderer;
import com.google.android.exoplayer.MediaCodecSelector;
import com.google.android.exoplayer.MediaCodecVideoTrackRenderer;
import com.google.android.exoplayer.TrackRenderer;
import com.google.android.exoplayer.audio.AudioCapabilities;
import com.google.android.exoplayer.drm.DrmSessionManager;
import com.google.android.exoplayer.extractor.Extractor;
import com.google.android.exoplayer.extractor.ExtractorSampleSource;
import com.google.android.exoplayer.text.SubtitleParser;
import com.google.android.exoplayer.text.TextTrackRenderer;
import com.google.android.exoplayer.upstream.BandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultAllocator;
import com.google.android.exoplayer.upstream.DefaultBandwidthMeter;
import com.google.android.exoplayer.upstream.DefaultUriDataSource;
import tv.danmaku.ijk.media.exo.demo.player.DemoPlayer;

/* loaded from: classes3.dex */
public class ExtractorRendererBuilder implements DemoPlayer.RendererBuilder {
    private static final int BUFFER_SEGMENT_COUNT = 256;
    private static final int BUFFER_SEGMENT_SIZE = 65536;
    private final Context context;
    private final Uri uri;
    private final String userAgent;

    public ExtractorRendererBuilder(Context context, String str, Uri uri) {
        this.context = context;
        this.userAgent = str;
        this.uri = uri;
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.RendererBuilder
    public void buildRenderers(DemoPlayer demoPlayer) {
        DefaultAllocator defaultAllocator = new DefaultAllocator(65536);
        Handler mainHandler = demoPlayer.getMainHandler();
        DefaultBandwidthMeter defaultBandwidthMeter = new DefaultBandwidthMeter(mainHandler, (BandwidthMeter.EventListener) null);
        ExtractorSampleSource extractorSampleSource = new ExtractorSampleSource(this.uri, new DefaultUriDataSource(this.context, defaultBandwidthMeter, this.userAgent), defaultAllocator, 16777216, mainHandler, demoPlayer, 0, new Extractor[0]);
        MediaCodecVideoTrackRenderer mediaCodecVideoTrackRenderer = new MediaCodecVideoTrackRenderer(this.context, extractorSampleSource, MediaCodecSelector.DEFAULT, 1, 5000L, mainHandler, demoPlayer, 50);
        MediaCodecAudioTrackRenderer mediaCodecAudioTrackRenderer = new MediaCodecAudioTrackRenderer(extractorSampleSource, MediaCodecSelector.DEFAULT, (DrmSessionManager) null, true, mainHandler, demoPlayer, AudioCapabilities.getCapabilities(this.context), 3);
        TextTrackRenderer textTrackRenderer = new TextTrackRenderer(extractorSampleSource, demoPlayer, mainHandler.getLooper(), new SubtitleParser[0]);
        TrackRenderer[] trackRendererArr = new TrackRenderer[4];
        trackRendererArr[0] = mediaCodecVideoTrackRenderer;
        trackRendererArr[1] = mediaCodecAudioTrackRenderer;
        trackRendererArr[2] = textTrackRenderer;
        demoPlayer.onRenderers(trackRendererArr, defaultBandwidthMeter);
    }

    @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.RendererBuilder
    public void cancel() {
    }
}
