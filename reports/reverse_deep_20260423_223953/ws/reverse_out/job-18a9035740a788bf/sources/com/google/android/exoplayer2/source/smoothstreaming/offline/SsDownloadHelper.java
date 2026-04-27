package com.google.android.exoplayer2.source.smoothstreaming.offline;

import android.net.Uri;
import com.google.android.exoplayer2.RenderersFactory;
import com.google.android.exoplayer2.drm.DrmSessionManager;
import com.google.android.exoplayer2.drm.FrameworkMediaCrypto;
import com.google.android.exoplayer2.offline.DownloadAction;
import com.google.android.exoplayer2.offline.DownloadHelper;
import com.google.android.exoplayer2.offline.StreamKey;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.source.smoothstreaming.manifest.SsManifest;
import com.google.android.exoplayer2.source.smoothstreaming.manifest.SsManifestParser;
import com.google.android.exoplayer2.source.smoothstreaming.manifest.SsUtil;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.ParsingLoadable;
import java.io.IOException;

/* JADX INFO: loaded from: classes2.dex */
public final class SsDownloadHelper extends DownloadHelper<SsManifest> {
    private final DataSource.Factory manifestDataSourceFactory;

    public SsDownloadHelper(Uri uri, DataSource.Factory manifestDataSourceFactory, RenderersFactory renderersFactory) {
        this(uri, manifestDataSourceFactory, DownloadHelper.DEFAULT_TRACK_SELECTOR_PARAMETERS, renderersFactory, null);
    }

    public SsDownloadHelper(Uri uri, DataSource.Factory manifestDataSourceFactory, DefaultTrackSelector.Parameters trackSelectorParameters, RenderersFactory renderersFactory, DrmSessionManager<FrameworkMediaCrypto> drmSessionManager) {
        super(DownloadAction.TYPE_SS, uri, null, trackSelectorParameters, renderersFactory, drmSessionManager);
        this.manifestDataSourceFactory = manifestDataSourceFactory;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public SsManifest loadManifest(Uri uri) throws IOException {
        DataSource dataSource = this.manifestDataSourceFactory.createDataSource();
        Uri fixedUri = SsUtil.fixManifestUri(uri);
        return (SsManifest) ParsingLoadable.load(dataSource, new SsManifestParser(), fixedUri, 4);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public TrackGroupArray[] getTrackGroupArrays(SsManifest manifest) {
        SsManifest.StreamElement[] streamElements = manifest.streamElements;
        TrackGroup[] trackGroups = new TrackGroup[streamElements.length];
        for (int i = 0; i < streamElements.length; i++) {
            trackGroups[i] = new TrackGroup(streamElements[i].formats);
        }
        return new TrackGroupArray[]{new TrackGroupArray(trackGroups)};
    }

    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    protected StreamKey toStreamKey(int periodIndex, int trackGroupIndex, int trackIndexInTrackGroup) {
        return new StreamKey(trackGroupIndex, trackIndexInTrackGroup);
    }
}
