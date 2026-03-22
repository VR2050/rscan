package p005b.p199l.p200a.p201a.p253z0;

import android.view.Surface;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.io.IOException;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1936b0;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p245m1.C2258g;

/* renamed from: b.l.a.a.z0.b */
/* loaded from: classes.dex */
public interface InterfaceC2409b {

    /* renamed from: b.l.a.a.z0.b$a */
    public static final class a {
        public a(long j2, AbstractC2404x0 abstractC2404x0, int i2, @Nullable InterfaceC2202y.a aVar, long j3, long j4, long j5) {
        }
    }

    void onAudioSessionId(a aVar, int i2);

    void onAudioUnderrun(a aVar, int i2, long j2, long j3);

    void onBandwidthEstimate(a aVar, int i2, long j2, long j3);

    void onDecoderDisabled(a aVar, int i2, C1944d c1944d);

    void onDecoderEnabled(a aVar, int i2, C1944d c1944d);

    void onDecoderInitialized(a aVar, int i2, String str, long j2);

    void onDecoderInputFormatChanged(a aVar, int i2, Format format);

    void onDownstreamFormatChanged(a aVar, InterfaceC2203z.c cVar);

    void onDroppedVideoFrames(a aVar, int i2, long j2);

    void onIsPlayingChanged(a aVar, boolean z);

    void onLoadCanceled(a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar);

    void onLoadCompleted(a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar);

    void onLoadError(a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar, IOException iOException, boolean z);

    void onLoadStarted(a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar);

    void onLoadingChanged(a aVar, boolean z);

    void onMediaPeriodCreated(a aVar);

    void onMediaPeriodReleased(a aVar);

    void onMetadata(a aVar, Metadata metadata);

    void onPlaybackParametersChanged(a aVar, C2262n0 c2262n0);

    void onPlaybackSuppressionReasonChanged(a aVar, int i2);

    void onPlayerError(a aVar, C1936b0 c1936b0);

    void onPlayerStateChanged(a aVar, boolean z, int i2);

    void onPositionDiscontinuity(a aVar, int i2);

    void onReadingStarted(a aVar);

    void onRenderedFirstFrame(a aVar, @Nullable Surface surface);

    void onRepeatModeChanged(a aVar, int i2);

    void onSeekProcessed(a aVar);

    void onSeekStarted(a aVar);

    void onShuffleModeChanged(a aVar, boolean z);

    void onSurfaceSizeChanged(a aVar, int i2, int i3);

    void onTimelineChanged(a aVar, int i2);

    void onTracksChanged(a aVar, TrackGroupArray trackGroupArray, C2258g c2258g);

    void onUpstreamDiscarded(a aVar, InterfaceC2203z.c cVar);

    void onVideoSizeChanged(a aVar, int i2, int i3, int i4, float f2);

    void onVolumeChanged(a aVar, float f2);
}
