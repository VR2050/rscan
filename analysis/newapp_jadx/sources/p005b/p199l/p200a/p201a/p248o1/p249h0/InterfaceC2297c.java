package p005b.p199l.p200a.p201a.p248o1.p249h0;

import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;
import java.io.File;
import java.io.IOException;
import java.util.NavigableSet;
import java.util.Set;

/* renamed from: b.l.a.a.o1.h0.c */
/* loaded from: classes.dex */
public interface InterfaceC2297c {

    /* renamed from: b.l.a.a.o1.h0.c$a */
    public static class a extends IOException {
        public a(String str) {
            super(str);
        }

        public a(Throwable th) {
            super(th);
        }

        public a(String str, Throwable th) {
            super(str, th);
        }
    }

    /* renamed from: b.l.a.a.o1.h0.c$b */
    public interface b {
        /* renamed from: a */
        void mo2212a(InterfaceC2297c interfaceC2297c, C2305k c2305k);

        /* renamed from: b */
        void mo2213b(InterfaceC2297c interfaceC2297c, C2305k c2305k, C2305k c2305k2);

        /* renamed from: c */
        void mo2214c(InterfaceC2297c interfaceC2297c, C2305k c2305k);
    }

    @WorkerThread
    /* renamed from: a */
    File mo2200a(String str, long j2, long j3);

    /* renamed from: b */
    InterfaceC2310p mo2201b(String str);

    @WorkerThread
    /* renamed from: c */
    void mo2202c(String str, C2311q c2311q);

    @WorkerThread
    /* renamed from: d */
    void mo2203d(C2305k c2305k);

    /* renamed from: e */
    long mo2204e(String str, long j2, long j3);

    /* renamed from: f */
    Set<String> mo2205f();

    @WorkerThread
    /* renamed from: g */
    void mo2206g(File file, long j2);

    /* renamed from: h */
    long mo2207h();

    @WorkerThread
    /* renamed from: i */
    C2305k mo2208i(String str, long j2);

    /* renamed from: j */
    void mo2209j(C2305k c2305k);

    @Nullable
    @WorkerThread
    /* renamed from: k */
    C2305k mo2210k(String str, long j2);

    /* renamed from: l */
    NavigableSet<C2305k> mo2211l(String str);

    @WorkerThread
    void release();
}
