package com.google.android.exoplayer2.source.hls.offline;

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
import com.google.android.exoplayer2.source.hls.playlist.HlsMasterPlaylist;
import com.google.android.exoplayer2.source.hls.playlist.HlsMediaPlaylist;
import com.google.android.exoplayer2.source.hls.playlist.HlsPlaylist;
import com.google.android.exoplayer2.source.hls.playlist.HlsPlaylistParser;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.ParsingLoadable;
import com.google.android.exoplayer2.util.Assertions;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public final class HlsDownloadHelper extends DownloadHelper<HlsPlaylist> {
    private final DataSource.Factory manifestDataSourceFactory;
    private int[] renditionGroups;

    public HlsDownloadHelper(Uri uri, DataSource.Factory manifestDataSourceFactory, RenderersFactory renderersFactory) {
        this(uri, manifestDataSourceFactory, DownloadHelper.DEFAULT_TRACK_SELECTOR_PARAMETERS, renderersFactory, null);
    }

    public HlsDownloadHelper(Uri uri, DataSource.Factory manifestDataSourceFactory, DefaultTrackSelector.Parameters trackSelectorParameters, RenderersFactory renderersFactory, DrmSessionManager<FrameworkMediaCrypto> drmSessionManager) {
        super(DownloadAction.TYPE_HLS, uri, null, trackSelectorParameters, renderersFactory, drmSessionManager);
        this.manifestDataSourceFactory = manifestDataSourceFactory;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public HlsPlaylist loadManifest(Uri uri) throws IOException {
        DataSource dataSource = this.manifestDataSourceFactory.createDataSource();
        return (HlsPlaylist) ParsingLoadable.load(dataSource, new HlsPlaylistParser(), uri, 4);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    public TrackGroupArray[] getTrackGroupArrays(HlsPlaylist playlist) {
        Assertions.checkNotNull(playlist);
        if (playlist instanceof HlsMediaPlaylist) {
            this.renditionGroups = new int[0];
            return new TrackGroupArray[]{TrackGroupArray.EMPTY};
        }
        HlsMasterPlaylist masterPlaylist = (HlsMasterPlaylist) playlist;
        TrackGroup[] trackGroups = new TrackGroup[3];
        this.renditionGroups = new int[3];
        int trackGroupIndex = 0;
        if (!masterPlaylist.variants.isEmpty()) {
            this.renditionGroups[0] = 0;
            int trackGroupIndex2 = 0 + 1;
            trackGroups[0] = new TrackGroup(toFormats(masterPlaylist.variants));
            trackGroupIndex = trackGroupIndex2;
        }
        if (!masterPlaylist.audios.isEmpty()) {
            this.renditionGroups[trackGroupIndex] = 1;
            trackGroups[trackGroupIndex] = new TrackGroup(toFormats(masterPlaylist.audios));
            trackGroupIndex++;
        }
        if (!masterPlaylist.subtitles.isEmpty()) {
            this.renditionGroups[trackGroupIndex] = 2;
            trackGroups[trackGroupIndex] = new TrackGroup(toFormats(masterPlaylist.subtitles));
            trackGroupIndex++;
        }
        return new TrackGroupArray[]{new TrackGroupArray((TrackGroup[]) Arrays.copyOf(trackGroups, trackGroupIndex))};
    }

    @Override // com.google.android.exoplayer2.offline.DownloadHelper
    protected StreamKey toStreamKey(int periodIndex, int trackGroupIndex, int trackIndexInTrackGroup) {
        return new StreamKey(this.renditionGroups[trackGroupIndex], trackIndexInTrackGroup);
    }

    private static Format[] toFormats(List<HlsMasterPlaylist.HlsUrl> hlsUrls) {
        Format[] formats = new Format[hlsUrls.size()];
        for (int i = 0; i < hlsUrls.size(); i++) {
            formats[i] = hlsUrls.get(i).format;
        }
        return formats;
    }
}
