package p005b.p199l.p200a.p201a.p202a1;

import android.media.AudioTrack;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import java.lang.reflect.Method;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.a1.p */
/* loaded from: classes.dex */
public final class C1924p {

    /* renamed from: a */
    public final a f3095a;

    /* renamed from: b */
    public final long[] f3096b;

    /* renamed from: c */
    @Nullable
    public AudioTrack f3097c;

    /* renamed from: d */
    public int f3098d;

    /* renamed from: e */
    public int f3099e;

    /* renamed from: f */
    @Nullable
    public C1923o f3100f;

    /* renamed from: g */
    public int f3101g;

    /* renamed from: h */
    public boolean f3102h;

    /* renamed from: i */
    public long f3103i;

    /* renamed from: j */
    public long f3104j;

    /* renamed from: k */
    public long f3105k;

    /* renamed from: l */
    @Nullable
    public Method f3106l;

    /* renamed from: m */
    public long f3107m;

    /* renamed from: n */
    public boolean f3108n;

    /* renamed from: o */
    public boolean f3109o;

    /* renamed from: p */
    public long f3110p;

    /* renamed from: q */
    public long f3111q;

    /* renamed from: r */
    public long f3112r;

    /* renamed from: s */
    public long f3113s;

    /* renamed from: t */
    public int f3114t;

    /* renamed from: u */
    public int f3115u;

    /* renamed from: v */
    public long f3116v;

    /* renamed from: w */
    public long f3117w;

    /* renamed from: x */
    public long f3118x;

    /* renamed from: y */
    public long f3119y;

    /* renamed from: b.l.a.a.a1.p$a */
    public interface a {
        /* renamed from: a */
        void mo1274a(int i2, long j2);

        /* renamed from: b */
        void mo1275b(long j2);

        /* renamed from: c */
        void mo1276c(long j2, long j3, long j4, long j5);

        /* renamed from: d */
        void mo1277d(long j2, long j3, long j4, long j5);
    }

    public C1924p(a aVar) {
        this.f3095a = aVar;
        if (C2344d0.f6035a >= 18) {
            try {
                this.f3106l = AudioTrack.class.getMethod("getLatency", null);
            } catch (NoSuchMethodException unused) {
            }
        }
        this.f3096b = new long[10];
    }

    /* renamed from: a */
    public final long m1271a(long j2) {
        return (j2 * 1000000) / this.f3101g;
    }

    /* renamed from: b */
    public final long m1272b() {
        AudioTrack audioTrack = this.f3097c;
        Objects.requireNonNull(audioTrack);
        if (this.f3116v != -9223372036854775807L) {
            return Math.min(this.f3119y, this.f3118x + ((((SystemClock.elapsedRealtime() * 1000) - this.f3116v) * this.f3101g) / 1000000));
        }
        int playState = audioTrack.getPlayState();
        if (playState == 1) {
            return 0L;
        }
        long playbackHeadPosition = 4294967295L & audioTrack.getPlaybackHeadPosition();
        if (this.f3102h) {
            if (playState == 2 && playbackHeadPosition == 0) {
                this.f3113s = this.f3111q;
            }
            playbackHeadPosition += this.f3113s;
        }
        if (C2344d0.f6035a <= 29) {
            if (playbackHeadPosition == 0 && this.f3111q > 0 && playState == 3) {
                if (this.f3117w == -9223372036854775807L) {
                    this.f3117w = SystemClock.elapsedRealtime();
                }
                return this.f3111q;
            }
            this.f3117w = -9223372036854775807L;
        }
        if (this.f3111q > playbackHeadPosition) {
            this.f3112r++;
        }
        this.f3111q = playbackHeadPosition;
        return playbackHeadPosition + (this.f3112r << 32);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:? A[RETURN, SYNTHETIC] */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m1273c(long r6) {
        /*
            r5 = this;
            long r0 = r5.m1272b()
            r2 = 0
            r3 = 1
            int r4 = (r6 > r0 ? 1 : (r6 == r0 ? 0 : -1))
            if (r4 > 0) goto L29
            boolean r6 = r5.f3102h
            if (r6 == 0) goto L26
            android.media.AudioTrack r6 = r5.f3097c
            java.util.Objects.requireNonNull(r6)
            int r6 = r6.getPlayState()
            r7 = 2
            if (r6 != r7) goto L26
            long r6 = r5.m1272b()
            r0 = 0
            int r4 = (r6 > r0 ? 1 : (r6 == r0 ? 0 : -1))
            if (r4 != 0) goto L26
            r6 = 1
            goto L27
        L26:
            r6 = 0
        L27:
            if (r6 == 0) goto L2a
        L29:
            r2 = 1
        L2a:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1924p.m1273c(long):boolean");
    }
}
