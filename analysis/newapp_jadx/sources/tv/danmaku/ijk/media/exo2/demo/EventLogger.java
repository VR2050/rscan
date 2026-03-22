package tv.danmaku.ijk.media.exo2.demo;

import android.os.SystemClock;
import android.view.Surface;
import androidx.annotation.Nullable;
import androidx.exifinterface.media.ExifInterface;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.emsg.EventMessage;
import com.google.android.exoplayer2.metadata.id3.ApicFrame;
import com.google.android.exoplayer2.metadata.id3.CommentFrame;
import com.google.android.exoplayer2.metadata.id3.GeobFrame;
import com.google.android.exoplayer2.metadata.id3.Id3Frame;
import com.google.android.exoplayer2.metadata.id3.PrivFrame;
import com.google.android.exoplayer2.metadata.id3.TextInformationFrame;
import com.google.android.exoplayer2.metadata.id3.UrlLinkFrame;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.io.IOException;
import java.text.NumberFormat;
import java.util.Locale;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1936b0;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.C2336p0;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p220h1.InterfaceC2082e;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p245m1.AbstractC2255d;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r;

/* loaded from: classes3.dex */
public final class EventLogger implements InterfaceC2368q0.a, InterfaceC2082e, InterfaceC1921m, InterfaceC2386r, InterfaceC2203z {
    private static final int MAX_TIMELINE_ITEM_LINES = 3;
    private static final String TAG = "EventLogger";
    private static final NumberFormat TIME_FORMAT;
    private final AbstractC2255d trackSelector;
    private final AbstractC2404x0.c window = new AbstractC2404x0.c();
    private final AbstractC2404x0.b period = new AbstractC2404x0.b();
    private final long startTimeMs = SystemClock.elapsedRealtime();

    static {
        NumberFormat numberFormat = NumberFormat.getInstance(Locale.US);
        TIME_FORMAT = numberFormat;
        numberFormat.setMinimumFractionDigits(2);
        numberFormat.setMaximumFractionDigits(2);
        numberFormat.setGroupingUsed(false);
    }

    public EventLogger(AbstractC2255d abstractC2255d) {
        this.trackSelector = abstractC2255d;
    }

    private static String getAdaptiveSupportString(int i2, int i3) {
        return i2 < 2 ? "N/A" : i3 != 0 ? i3 != 8 ? i3 != 16 ? "?" : "YES" : "YES_NOT_SEAMLESS" : "NO";
    }

    private static String getDiscontinuityReasonString(int i2) {
        return i2 != 0 ? i2 != 1 ? i2 != 2 ? i2 != 4 ? "?" : "INTERNAL" : "SEEK_ADJUSTMENT" : "SEEK" : "PERIOD_TRANSITION";
    }

    private static String getFormatSupportString(int i2) {
        return i2 != 0 ? i2 != 1 ? i2 != 2 ? i2 != 3 ? i2 != 4 ? "?" : "YES" : "NO_EXCEEDS_CAPABILITIES" : "NO_UNSUPPORTED_DRM" : "NO_UNSUPPORTED_TYPE" : "NO";
    }

    private static String getRepeatModeString(int i2) {
        return i2 != 0 ? i2 != 1 ? i2 != 2 ? "?" : "ALL" : "ONE" : "OFF";
    }

    private String getSessionTimeString() {
        return getTimeString(SystemClock.elapsedRealtime() - this.startTimeMs);
    }

    private static String getStateString(int i2) {
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? i2 != 4 ? "?" : ExifInterface.LONGITUDE_EAST : "R" : "B" : "I";
    }

    private static String getTimeString(long j2) {
        return j2 == -9223372036854775807L ? "?" : TIME_FORMAT.format(j2 / 1000.0f);
    }

    private static String getTrackStatusString(InterfaceC2257f interfaceC2257f, TrackGroup trackGroup, int i2) {
        return getTrackStatusString((interfaceC2257f == null || interfaceC2257f.mo2149a() != trackGroup || interfaceC2257f.mo2158q(i2) == -1) ? false : true);
    }

    private static String getTrackStatusString(boolean z) {
        return z ? "[X]" : "[ ]";
    }

    private void printInternalError(String str, Exception exc) {
        getSessionTimeString();
    }

    private void printMetadata(Metadata metadata, String str) {
        int i2 = 0;
        while (true) {
            Metadata.Entry[] entryArr = metadata.f9273c;
            if (i2 >= entryArr.length) {
                return;
            }
            Metadata.Entry entry = entryArr[i2];
            if (entry instanceof TextInformationFrame) {
                TextInformationFrame textInformationFrame = (TextInformationFrame) entry;
                String.format("%s: value=%s", textInformationFrame.f9324c, textInformationFrame.f9336f);
            } else if (entry instanceof UrlLinkFrame) {
                UrlLinkFrame urlLinkFrame = (UrlLinkFrame) entry;
                String.format("%s: url=%s", urlLinkFrame.f9324c, urlLinkFrame.f9338f);
            } else if (entry instanceof PrivFrame) {
                PrivFrame privFrame = (PrivFrame) entry;
                String.format("%s: owner=%s", privFrame.f9324c, privFrame.f9333e);
            } else if (entry instanceof GeobFrame) {
                GeobFrame geobFrame = (GeobFrame) entry;
                String.format("%s: mimeType=%s, filename=%s, description=%s", geobFrame.f9324c, geobFrame.f9320e, geobFrame.f9321f, geobFrame.f9322g);
            } else if (entry instanceof ApicFrame) {
                ApicFrame apicFrame = (ApicFrame) entry;
                String.format("%s: mimeType=%s, description=%s", apicFrame.f9324c, apicFrame.f9301e, apicFrame.f9302f);
            } else if (entry instanceof CommentFrame) {
                CommentFrame commentFrame = (CommentFrame) entry;
                String.format("%s: language=%s, description=%s", commentFrame.f9324c, commentFrame.f9317e, commentFrame.f9318f);
            } else if (entry instanceof Id3Frame) {
                String.format("%s", ((Id3Frame) entry).f9324c);
            } else if (entry instanceof EventMessage) {
                EventMessage eventMessage = (EventMessage) entry;
                String.format("EMSG: scheme=%s, id=%d, value=%s", eventMessage.f9276f, Long.valueOf(eventMessage.f9279i), eventMessage.f9277g);
            }
            i2++;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public void onAudioDecoderInitialized(String str, long j2, long j3) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public void onAudioDisabled(C1944d c1944d) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public void onAudioEnabled(C1944d c1944d) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public void onAudioInputFormatChanged(Format format) {
        getSessionTimeString();
        Format.m4036O(format);
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public void onAudioSessionId(int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public void onAudioSinkUnderrun(int i2, long j2, long j3) {
        printInternalError("audioTrackUnderrun [" + i2 + ", " + j2 + ", " + j3 + "]", null);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onDownstreamFormatChanged(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.c cVar) {
    }

    public void onDrmKeysLoaded() {
        getSessionTimeString();
    }

    public void onDrmKeysRemoved() {
        getSessionTimeString();
    }

    public void onDrmKeysRestored() {
        getSessionTimeString();
    }

    public void onDrmSessionAcquired() {
    }

    public void onDrmSessionManagerError(Exception exc) {
        printInternalError("drmSessionManagerError", exc);
    }

    public void onDrmSessionReleased() {
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public void onDroppedFrames(int i2, long j2) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onIsPlayingChanged(boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onLoadCanceled(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onLoadCompleted(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onLoadError(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar, IOException iOException, boolean z) {
        printInternalError("loadError", iOException);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onLoadStarted(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onLoadingChanged(boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onMediaPeriodCreated(int i2, InterfaceC2202y.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onMediaPeriodReleased(int i2, InterfaceC2202y.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2082e
    public void onMetadata(Metadata metadata) {
        printMetadata(metadata, "  ");
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlaybackParametersChanged(C2262n0 c2262n0) {
        String.format("[speed=%.2f, pitch=%.2f]", Float.valueOf(c2262n0.f5669b), Float.valueOf(c2262n0.f5670c));
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlaybackSuppressionReasonChanged(int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlayerError(C1936b0 c1936b0) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlayerStateChanged(boolean z, int i2) {
        getSessionTimeString();
        getStateString(i2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPositionDiscontinuity(int i2) {
        getDiscontinuityReasonString(i2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onReadingStarted(int i2, InterfaceC2202y.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public void onRenderedFirstFrame(Surface surface) {
        String str = "renderedFirstFrame [" + surface + "]";
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onRepeatModeChanged(int i2) {
        getRepeatModeString(i2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onSeekProcessed() {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onShuffleModeEnabledChanged(boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public /* bridge */ /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, int i2) {
        C2336p0.m2294j(this, abstractC2404x0, i2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onTimelineChanged(AbstractC2404x0 abstractC2404x0, Object obj, int i2) {
        int mo1833i = abstractC2404x0.mo1833i();
        int mo1836p = abstractC2404x0.mo1836p();
        for (int i3 = 0; i3 < Math.min(mo1833i, 3); i3++) {
            abstractC2404x0.m2687f(i3, this.period);
            getTimeString(C2399v.m2669b(this.period.f6369c));
        }
        for (int i4 = 0; i4 < Math.min(mo1836p, 3); i4++) {
            abstractC2404x0.m2690n(i4, this.window);
            getTimeString(this.window.m2698a());
            AbstractC2404x0.c cVar = this.window;
            boolean z = cVar.f6376e;
            boolean z2 = cVar.f6377f;
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onTracksChanged(TrackGroupArray trackGroupArray, C2258g c2258g) {
        AbstractC2255d.a aVar = this.trackSelector.f5647b;
        if (aVar == null) {
            return;
        }
        for (int i2 = 0; i2 < aVar.f5648a; i2++) {
            TrackGroupArray trackGroupArray2 = aVar.f5651d[i2];
            InterfaceC2257f interfaceC2257f = c2258g.f5660b[i2];
            if (trackGroupArray2.f9397e > 0) {
                for (int i3 = 0; i3 < trackGroupArray2.f9397e; i3++) {
                    TrackGroup trackGroup = trackGroupArray2.f9398f[i3];
                    getAdaptiveSupportString(trackGroup.f9393c, aVar.m2162a(i2, i3, false));
                    for (int i4 = 0; i4 < trackGroup.f9393c; i4++) {
                        getTrackStatusString(interfaceC2257f, trackGroup, i4);
                        getFormatSupportString(aVar.f5653f[i2][i3][i4] & 7);
                        Format.m4036O(trackGroup.f9394e[i4]);
                    }
                }
                if (interfaceC2257f != null) {
                    int i5 = 0;
                    while (true) {
                        if (i5 >= interfaceC2257f.length()) {
                            break;
                        }
                        Metadata metadata = interfaceC2257f.mo2152e(i5).f9243j;
                        if (metadata != null) {
                            printMetadata(metadata, "      ");
                            break;
                        }
                        i5++;
                    }
                }
            }
        }
        TrackGroupArray trackGroupArray3 = aVar.f5654g;
        if (trackGroupArray3.f9397e > 0) {
            for (int i6 = 0; i6 < trackGroupArray3.f9397e; i6++) {
                TrackGroup trackGroup2 = trackGroupArray3.f9398f[i6];
                for (int i7 = 0; i7 < trackGroup2.f9393c; i7++) {
                    getTrackStatusString(false);
                    getFormatSupportString(0);
                    Format.m4036O(trackGroup2.f9394e[i7]);
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public void onUpstreamDiscarded(int i2, InterfaceC2202y.a aVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public void onVideoDecoderInitialized(String str, long j2, long j3) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public void onVideoDisabled(C1944d c1944d) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public void onVideoEnabled(C1944d c1944d) {
        getSessionTimeString();
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public void onVideoInputFormatChanged(Format format) {
        getSessionTimeString();
        Format.m4036O(format);
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public void onVideoSizeChanged(int i2, int i3, int i4, float f2) {
    }
}
