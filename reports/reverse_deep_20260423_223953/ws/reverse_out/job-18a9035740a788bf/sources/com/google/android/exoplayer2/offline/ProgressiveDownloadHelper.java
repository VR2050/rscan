package com.google.android.exoplayer2.offline;

import android.net.Uri;
import android.os.Handler;
import com.google.android.exoplayer2.Renderer;
import com.google.android.exoplayer2.RenderersFactory;
import com.google.android.exoplayer2.audio.AudioRendererEventListener;
import com.google.android.exoplayer2.drm.DrmSessionManager;
import com.google.android.exoplayer2.metadata.MetadataOutput;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.text.TextOutput;
import com.google.android.exoplayer2.video.VideoRendererEventListener;

/* JADX INFO: loaded from: classes2.dex */
public final class ProgressiveDownloadHelper extends DownloadHelper<Void> {
    public ProgressiveDownloadHelper(Uri uri) {
        this(uri, null);
    }

    public ProgressiveDownloadHelper(Uri uri, String cacheKey) {
        super(DownloadAction.TYPE_PROGRESSIVE, uri, cacheKey, DownloadHelper.DEFAULT_TRACK_SELECTOR_PARAMETERS, new RenderersFactory() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$ProgressiveDownloadHelper$yyGfRS-dIiTzRfwebkHqjls-B3k
            @Override // com.google.android.exoplayer2.RenderersFactory
            public final Renderer[] createRenderers(Handler handler, VideoRendererEventListener videoRendererEventListener, AudioRendererEventListener audioRendererEventListener, TextOutput textOutput, MetadataOutput metadataOutput, DrmSessionManager drmSessionManager) {
                return ProgressiveDownloadHelper.lambda$new$0(handler, videoRendererEventListener, audioRendererEventListener, textOutput, metadataOutput, drmSessionManager);
            }
        }, null);
    }

    static /* synthetic */ Renderer[] lambda$new$0(Handler handler, VideoRendererEventListener videoListener, AudioRendererEventListener audioListener, TextOutput metadata, MetadataOutput text, DrmSessionManager drm) {
        return new Renderer[0];
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public Void loadManifest(Uri uri) {
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public TrackGroupArray[] getTrackGroupArrays(Void manifest) {
        return new TrackGroupArray[]{TrackGroupArray.EMPTY};
    }

    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    protected StreamKey toStreamKey(int periodIndex, int trackGroupIndex, int trackIndexInTrackGroup) {
        return new StreamKey(periodIndex, trackGroupIndex, trackIndexInTrackGroup);
    }
}
