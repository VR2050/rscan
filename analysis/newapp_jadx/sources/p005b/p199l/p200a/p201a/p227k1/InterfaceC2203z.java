package p005b.p199l.p200a.p201a.p227k1;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.CheckResult;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p248o1.C2324p;

/* renamed from: b.l.a.a.k1.z */
/* loaded from: classes.dex */
public interface InterfaceC2203z {

    /* renamed from: b.l.a.a.k1.z$b */
    public static final class b {

        /* renamed from: a */
        public final Map<String, List<String>> f5258a;

        public b(C2324p c2324p, Uri uri, Map<String, List<String>> map, long j2, long j3, long j4) {
            this.f5258a = map;
        }
    }

    /* renamed from: b.l.a.a.k1.z$c */
    public static final class c {

        /* renamed from: a */
        public final int f5259a;

        /* renamed from: b */
        public final int f5260b;

        /* renamed from: c */
        @Nullable
        public final Format f5261c;

        /* renamed from: d */
        public final int f5262d;

        /* renamed from: e */
        @Nullable
        public final Object f5263e;

        /* renamed from: f */
        public final long f5264f;

        /* renamed from: g */
        public final long f5265g;

        public c(int i2, int i3, @Nullable Format format, int i4, @Nullable Object obj, long j2, long j3) {
            this.f5259a = i2;
            this.f5260b = i3;
            this.f5261c = format;
            this.f5262d = i4;
            this.f5263e = obj;
            this.f5264f = j2;
            this.f5265g = j3;
        }
    }

    void onDownstreamFormatChanged(int i2, @Nullable InterfaceC2202y.a aVar, c cVar);

    void onLoadCanceled(int i2, @Nullable InterfaceC2202y.a aVar, b bVar, c cVar);

    void onLoadCompleted(int i2, @Nullable InterfaceC2202y.a aVar, b bVar, c cVar);

    void onLoadError(int i2, @Nullable InterfaceC2202y.a aVar, b bVar, c cVar, IOException iOException, boolean z);

    void onLoadStarted(int i2, @Nullable InterfaceC2202y.a aVar, b bVar, c cVar);

    void onMediaPeriodCreated(int i2, InterfaceC2202y.a aVar);

    void onMediaPeriodReleased(int i2, InterfaceC2202y.a aVar);

    void onReadingStarted(int i2, InterfaceC2202y.a aVar);

    void onUpstreamDiscarded(int i2, InterfaceC2202y.a aVar, c cVar);

    /* renamed from: b.l.a.a.k1.z$a */
    public static final class a {

        /* renamed from: a */
        public final int f5252a;

        /* renamed from: b */
        @Nullable
        public final InterfaceC2202y.a f5253b;

        /* renamed from: c */
        public final CopyOnWriteArrayList<C5114a> f5254c;

        /* renamed from: d */
        public final long f5255d;

        /* renamed from: b.l.a.a.k1.z$a$a, reason: collision with other inner class name */
        public static final class C5114a {

            /* renamed from: a */
            public final Handler f5256a;

            /* renamed from: b */
            public final InterfaceC2203z f5257b;

            public C5114a(Handler handler, InterfaceC2203z interfaceC2203z) {
                this.f5256a = handler;
                this.f5257b = interfaceC2203z;
            }
        }

        public a() {
            this.f5254c = new CopyOnWriteArrayList<>();
            this.f5252a = 0;
            this.f5253b = null;
            this.f5255d = 0L;
        }

        /* renamed from: a */
        public final long m2025a(long j2) {
            long m2669b = C2399v.m2669b(j2);
            if (m2669b == -9223372036854775807L) {
                return -9223372036854775807L;
            }
            return this.f5255d + m2669b;
        }

        /* renamed from: b */
        public void m2026b(int i2, @Nullable Format format, int i3, @Nullable Object obj, long j2) {
            m2027c(new c(1, i2, format, i3, obj, m2025a(j2), -9223372036854775807L));
        }

        /* renamed from: c */
        public void m2027c(final c cVar) {
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.e
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar = InterfaceC2203z.a.this;
                        interfaceC2203z.onDownstreamFormatChanged(aVar.f5252a, aVar.f5253b, cVar);
                    }
                });
            }
        }

        /* renamed from: d */
        public void m2028d(final b bVar, final c cVar) {
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.f
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar = InterfaceC2203z.a.this;
                        interfaceC2203z.onLoadCanceled(aVar.f5252a, aVar.f5253b, bVar, cVar);
                    }
                });
            }
        }

        /* renamed from: e */
        public void m2029e(C2324p c2324p, Uri uri, Map<String, List<String>> map, int i2, int i3, @Nullable Format format, int i4, @Nullable Object obj, long j2, long j3, long j4, long j5, long j6) {
            m2028d(new b(c2324p, uri, map, j4, j5, j6), new c(i2, i3, format, i4, obj, m2025a(j2), m2025a(j3)));
        }

        /* renamed from: f */
        public void m2030f(C2324p c2324p, Uri uri, Map<String, List<String>> map, int i2, long j2, long j3, long j4) {
            m2029e(c2324p, uri, map, i2, -1, null, 0, null, -9223372036854775807L, -9223372036854775807L, j2, j3, j4);
        }

        /* renamed from: g */
        public void m2031g(final b bVar, final c cVar) {
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.h
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar = InterfaceC2203z.a.this;
                        interfaceC2203z.onLoadCompleted(aVar.f5252a, aVar.f5253b, bVar, cVar);
                    }
                });
            }
        }

        /* renamed from: h */
        public void m2032h(C2324p c2324p, Uri uri, Map<String, List<String>> map, int i2, int i3, @Nullable Format format, int i4, @Nullable Object obj, long j2, long j3, long j4, long j5, long j6) {
            m2031g(new b(c2324p, uri, map, j4, j5, j6), new c(i2, i3, format, i4, obj, m2025a(j2), m2025a(j3)));
        }

        /* renamed from: i */
        public void m2033i(C2324p c2324p, Uri uri, Map<String, List<String>> map, int i2, long j2, long j3, long j4) {
            m2032h(c2324p, uri, map, i2, -1, null, 0, null, -9223372036854775807L, -9223372036854775807L, j2, j3, j4);
        }

        /* renamed from: j */
        public void m2034j(final b bVar, final c cVar, final IOException iOException, final boolean z) {
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.d
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar = InterfaceC2203z.a.this;
                        interfaceC2203z.onLoadError(aVar.f5252a, aVar.f5253b, bVar, cVar, iOException, z);
                    }
                });
            }
        }

        /* renamed from: k */
        public void m2035k(C2324p c2324p, Uri uri, Map<String, List<String>> map, int i2, int i3, @Nullable Format format, int i4, @Nullable Object obj, long j2, long j3, long j4, long j5, long j6, IOException iOException, boolean z) {
            m2034j(new b(c2324p, uri, map, j4, j5, j6), new c(i2, i3, format, i4, obj, m2025a(j2), m2025a(j3)), iOException, z);
        }

        /* renamed from: l */
        public void m2036l(C2324p c2324p, Uri uri, Map<String, List<String>> map, int i2, long j2, long j3, long j4, IOException iOException, boolean z) {
            m2035k(c2324p, uri, map, i2, -1, null, 0, null, -9223372036854775807L, -9223372036854775807L, j2, j3, j4, iOException, z);
        }

        /* renamed from: m */
        public void m2037m(final b bVar, final c cVar) {
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.b
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar = InterfaceC2203z.a.this;
                        interfaceC2203z.onLoadStarted(aVar.f5252a, aVar.f5253b, bVar, cVar);
                    }
                });
            }
        }

        /* renamed from: n */
        public void m2038n(C2324p c2324p, int i2, int i3, @Nullable Format format, int i4, @Nullable Object obj, long j2, long j3, long j4) {
            m2037m(new b(c2324p, c2324p.f5933a, Collections.emptyMap(), j4, 0L, 0L), new c(i2, i3, format, i4, obj, m2025a(j2), m2025a(j3)));
        }

        /* renamed from: o */
        public void m2039o(C2324p c2324p, int i2, long j2) {
            m2038n(c2324p, i2, -1, null, 0, null, -9223372036854775807L, -9223372036854775807L, j2);
        }

        /* renamed from: p */
        public void m2040p() {
            final InterfaceC2202y.a aVar = this.f5253b;
            Objects.requireNonNull(aVar);
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.j
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar2 = InterfaceC2203z.a.this;
                        interfaceC2203z.onMediaPeriodCreated(aVar2.f5252a, aVar);
                    }
                });
            }
        }

        /* renamed from: q */
        public void m2041q() {
            final InterfaceC2202y.a aVar = this.f5253b;
            Objects.requireNonNull(aVar);
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.g
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar2 = InterfaceC2203z.a.this;
                        interfaceC2203z.onMediaPeriodReleased(aVar2.f5252a, aVar);
                    }
                });
            }
        }

        /* renamed from: r */
        public final void m2042r(Handler handler, Runnable runnable) {
            if (handler.getLooper() == Looper.myLooper()) {
                runnable.run();
            } else {
                handler.post(runnable);
            }
        }

        /* renamed from: s */
        public void m2043s() {
            final InterfaceC2202y.a aVar = this.f5253b;
            Objects.requireNonNull(aVar);
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.i
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar2 = InterfaceC2203z.a.this;
                        interfaceC2203z.onReadingStarted(aVar2.f5252a, aVar);
                    }
                });
            }
        }

        /* renamed from: t */
        public void m2044t(final c cVar) {
            final InterfaceC2202y.a aVar = this.f5253b;
            Objects.requireNonNull(aVar);
            Iterator<C5114a> it = this.f5254c.iterator();
            while (it.hasNext()) {
                C5114a next = it.next();
                final InterfaceC2203z interfaceC2203z = next.f5257b;
                m2042r(next.f5256a, new Runnable() { // from class: b.l.a.a.k1.c
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2203z.a aVar2 = InterfaceC2203z.a.this;
                        interfaceC2203z.onUpstreamDiscarded(aVar2.f5252a, aVar, cVar);
                    }
                });
            }
        }

        @CheckResult
        /* renamed from: u */
        public a m2045u(int i2, @Nullable InterfaceC2202y.a aVar, long j2) {
            return new a(this.f5254c, i2, aVar, j2);
        }

        public a(CopyOnWriteArrayList<C5114a> copyOnWriteArrayList, int i2, @Nullable InterfaceC2202y.a aVar, long j2) {
            this.f5254c = copyOnWriteArrayList;
            this.f5252a = i2;
            this.f5253b = aVar;
            this.f5255d = j2;
        }
    }
}
