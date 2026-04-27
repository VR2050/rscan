package com.google.android.exoplayer2.source.dash.offline;

import android.net.Uri;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.RenderersFactory;
import com.google.android.exoplayer2.drm.DrmSessionManager;
import com.google.android.exoplayer2.drm.FrameworkMediaCrypto;
import com.google.android.exoplayer2.offline.DownloadAction;
import com.google.android.exoplayer2.offline.DownloadHelper;
import com.google.android.exoplayer2.offline.StreamKey;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.source.dash.manifest.AdaptationSet;
import com.google.android.exoplayer2.source.dash.manifest.DashManifest;
import com.google.android.exoplayer2.source.dash.manifest.DashManifestParser;
import com.google.android.exoplayer2.source.dash.manifest.Representation;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.ParsingLoadable;
import java.io.IOException;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public final class DashDownloadHelper extends DownloadHelper<DashManifest> {
    private final DataSource.Factory manifestDataSourceFactory;

    public DashDownloadHelper(Uri uri, DataSource.Factory manifestDataSourceFactory, RenderersFactory renderersFactory) {
        this(uri, manifestDataSourceFactory, DownloadHelper.DEFAULT_TRACK_SELECTOR_PARAMETERS, renderersFactory, null);
    }

    public DashDownloadHelper(Uri uri, DataSource.Factory manifestDataSourceFactory, DefaultTrackSelector.Parameters trackSelectorParameters, RenderersFactory renderersFactory, DrmSessionManager<FrameworkMediaCrypto> drmSessionManager) {
        super(DownloadAction.TYPE_DASH, uri, null, trackSelectorParameters, renderersFactory, drmSessionManager);
        this.manifestDataSourceFactory = manifestDataSourceFactory;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public DashManifest loadManifest(Uri uri) throws IOException {
        DataSource dataSource = this.manifestDataSourceFactory.createDataSource();
        return (DashManifest) ParsingLoadable.load(dataSource, new DashManifestParser(), uri, 4);
    }

    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public TrackGroupArray[] getTrackGroupArrays(DashManifest manifest) {
        int periodCount = manifest.getPeriodCount();
        TrackGroupArray[] trackGroupArrays = new TrackGroupArray[periodCount];
        for (int periodIndex = 0; periodIndex < periodCount; periodIndex++) {
            List<AdaptationSet> adaptationSets = manifest.getPeriod(periodIndex).adaptationSets;
            TrackGroup[] trackGroups = new TrackGroup[adaptationSets.size()];
            for (int i = 0; i < trackGroups.length; i++) {
                List<Representation> representations = adaptationSets.get(i).representations;
                Format[] formats = new Format[representations.size()];
                int representationsCount = representations.size();
                for (int j = 0; j < representationsCount; j++) {
                    formats[j] = representations.get(j).format;
                }
                trackGroups[i] = new TrackGroup(formats);
            }
            trackGroupArrays[periodIndex] = new TrackGroupArray(trackGroups);
        }
        return trackGroupArrays;
    }

    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    protected StreamKey toStreamKey(int periodIndex, int trackGroupIndex, int trackIndexInTrackGroup) {
        return new StreamKey(periodIndex, trackGroupIndex, trackIndexInTrackGroup);
    }
}
