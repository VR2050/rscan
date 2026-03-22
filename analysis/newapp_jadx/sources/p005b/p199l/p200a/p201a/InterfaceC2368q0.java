package p005b.p199l.p200a.p201a;

import android.os.Looper;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.source.TrackGroupArray;
import p005b.p199l.p200a.p201a.p245m1.C2258g;

/* renamed from: b.l.a.a.q0 */
/* loaded from: classes.dex */
public interface InterfaceC2368q0 {

    /* renamed from: b.l.a.a.q0$a */
    public interface a {
        void onIsPlayingChanged(boolean z);

        void onLoadingChanged(boolean z);

        void onPlaybackParametersChanged(C2262n0 c2262n0);

        void onPlaybackSuppressionReasonChanged(int i2);

        void onPlayerError(C1936b0 c1936b0);

        void onPlayerStateChanged(boolean z, int i2);

        void onPositionDiscontinuity(int i2);

        void onRepeatModeChanged(int i2);

        void onSeekProcessed();

        void onShuffleModeEnabledChanged(boolean z);

        void onTimelineChanged(AbstractC2404x0 abstractC2404x0, int i2);

        @Deprecated
        void onTimelineChanged(AbstractC2404x0 abstractC2404x0, @Nullable Object obj, int i2);

        void onTracksChanged(TrackGroupArray trackGroupArray, C2258g c2258g);
    }

    /* renamed from: b.l.a.a.q0$b */
    public interface b {
    }

    /* renamed from: b.l.a.a.q0$c */
    public interface c {
    }

    /* renamed from: A */
    boolean mo1340A();

    /* renamed from: B */
    long mo1341B();

    /* renamed from: C */
    C2258g mo1342C();

    /* renamed from: D */
    int mo1343D(int i2);

    @Nullable
    /* renamed from: E */
    b mo1344E();

    /* renamed from: a */
    int mo1354a();

    /* renamed from: b */
    C2262n0 mo1355b();

    /* renamed from: c */
    boolean mo1356c();

    /* renamed from: d */
    void mo1357d(int i2);

    /* renamed from: e */
    int mo1358e();

    /* renamed from: f */
    long mo1359f();

    /* renamed from: g */
    void mo1360g(int i2, long j2);

    long getCurrentPosition();

    long getDuration();

    /* renamed from: h */
    boolean mo1361h();

    boolean hasNext();

    boolean hasPrevious();

    /* renamed from: i */
    void mo1362i(boolean z);

    boolean isPlaying();

    @Nullable
    /* renamed from: j */
    C1936b0 mo1363j();

    /* renamed from: k */
    boolean mo2610k();

    /* renamed from: l */
    void mo1364l(a aVar);

    /* renamed from: m */
    int mo1365m();

    /* renamed from: n */
    void mo1366n(a aVar);

    /* renamed from: o */
    int mo1367o();

    /* renamed from: p */
    void mo1368p(boolean z);

    @Nullable
    /* renamed from: q */
    c mo1369q();

    /* renamed from: r */
    long mo1370r();

    /* renamed from: s */
    int mo2611s();

    /* renamed from: t */
    long mo1371t();

    /* renamed from: u */
    int mo1372u();

    /* renamed from: v */
    int mo2612v();

    /* renamed from: w */
    int mo1373w();

    /* renamed from: x */
    TrackGroupArray mo1374x();

    /* renamed from: y */
    AbstractC2404x0 mo1375y();

    /* renamed from: z */
    Looper mo1376z();
}
