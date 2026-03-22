package p005b.p199l.p200a.p201a.p248o1.p249h0;

import android.os.ConditionVariable;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.h0.u */
/* loaded from: classes.dex */
public final class C2315u implements InterfaceC2297c {

    /* renamed from: a */
    public static final HashSet<File> f5902a = new HashSet<>();

    /* renamed from: b */
    public final File f5903b;

    /* renamed from: c */
    public final InterfaceC2302h f5904c;

    /* renamed from: d */
    public final C2308n f5905d;

    /* renamed from: e */
    public final HashMap<String, ArrayList<InterfaceC2297c.b>> f5906e;

    /* renamed from: f */
    public final Random f5907f;

    /* renamed from: g */
    public final boolean f5908g;

    /* renamed from: h */
    public long f5909h;

    /* renamed from: i */
    public long f5910i;

    /* renamed from: j */
    public boolean f5911j;

    /* renamed from: k */
    public InterfaceC2297c.a f5912k;

    @Deprecated
    public C2315u(File file, InterfaceC2302h interfaceC2302h) {
        boolean add;
        C2308n c2308n = new C2308n(null, file, null, false, true);
        synchronized (C2315u.class) {
            add = f5902a.add(file.getAbsoluteFile());
        }
        if (!add) {
            throw new IllegalStateException(C1499a.m634t("Another SimpleCache instance uses the folder: ", file));
        }
        this.f5903b = file;
        this.f5904c = interfaceC2302h;
        this.f5905d = c2308n;
        this.f5906e = new HashMap<>();
        this.f5907f = new Random();
        this.f5908g = true;
        this.f5909h = -1L;
        ConditionVariable conditionVariable = new ConditionVariable();
        new C2314t(this, "SimpleCache.initialize()", conditionVariable).start();
        conditionVariable.block();
    }

    /* renamed from: m */
    public static void m2254m(C2315u c2315u) {
        long j2;
        if (!c2315u.f5903b.exists() && !c2315u.f5903b.mkdirs()) {
            StringBuilder m586H = C1499a.m586H("Failed to create cache directory: ");
            m586H.append(c2315u.f5903b);
            c2315u.f5912k = new InterfaceC2297c.a(m586H.toString());
            return;
        }
        File[] listFiles = c2315u.f5903b.listFiles();
        if (listFiles == null) {
            StringBuilder m586H2 = C1499a.m586H("Failed to list cache directory files: ");
            m586H2.append(c2315u.f5903b);
            c2315u.f5912k = new InterfaceC2297c.a(m586H2.toString());
            return;
        }
        int length = listFiles.length;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                j2 = -1;
                break;
            }
            File file = listFiles[i2];
            String name = file.getName();
            if (name.endsWith(".uid")) {
                try {
                    j2 = Long.parseLong(name.substring(0, name.indexOf(46)), 16);
                    break;
                } catch (NumberFormatException unused) {
                    String str = "Malformed UID file: " + file;
                    file.delete();
                }
            }
            i2++;
        }
        c2315u.f5909h = j2;
        if (j2 == -1) {
            try {
                c2315u.f5909h = m2255p(c2315u.f5903b);
            } catch (IOException e2) {
                StringBuilder m586H3 = C1499a.m586H("Failed to create cache UID: ");
                m586H3.append(c2315u.f5903b);
                c2315u.f5912k = new InterfaceC2297c.a(m586H3.toString(), e2);
                return;
            }
        }
        try {
            c2315u.f5905d.m2233e(c2315u.f5909h);
            c2315u.m2259q(c2315u.f5903b, true, listFiles, null);
            C2308n c2308n = c2315u.f5905d;
            int size = c2308n.f5875a.size();
            String[] strArr = new String[size];
            c2308n.f5875a.keySet().toArray(strArr);
            for (int i3 = 0; i3 < size; i3++) {
                c2308n.m2234f(strArr[i3]);
            }
            try {
                c2315u.f5905d.m2235g();
            } catch (IOException unused2) {
            }
        } catch (IOException e3) {
            StringBuilder m586H4 = C1499a.m586H("Failed to initialize cache indices: ");
            m586H4.append(c2315u.f5903b);
            c2315u.f5912k = new InterfaceC2297c.a(m586H4.toString(), e3);
        }
    }

    /* renamed from: p */
    public static long m2255p(File file) {
        long nextLong = new SecureRandom().nextLong();
        long abs = nextLong == Long.MIN_VALUE ? 0L : Math.abs(nextLong);
        File file2 = new File(file, C1499a.m637w(Long.toString(abs, 16), ".uid"));
        if (file2.createNewFile()) {
            return abs;
        }
        throw new IOException(C1499a.m634t("Failed to create UID file: ", file2));
    }

    /* renamed from: u */
    public static synchronized void m2256u(File file) {
        synchronized (C2315u.class) {
            f5902a.remove(file.getAbsoluteFile());
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: a */
    public synchronized File mo2200a(String str, long j2, long j3) {
        C2307m c2307m;
        File file;
        C4195m.m4771I(!this.f5911j);
        m2258o();
        c2307m = this.f5905d.f5875a.get(str);
        Objects.requireNonNull(c2307m);
        C4195m.m4771I(c2307m.f5874e);
        if (!this.f5903b.exists()) {
            this.f5903b.mkdirs();
            m2261s();
        }
        C2313s c2313s = (C2313s) this.f5904c;
        Objects.requireNonNull(c2313s);
        if (j3 != -1) {
            c2313s.m2253d(this, j3);
        }
        file = new File(this.f5903b, Integer.toString(this.f5907f.nextInt(10)));
        if (!file.exists()) {
            file.mkdir();
        }
        return C2316v.m2264c(file, c2307m.f5870a, j2, System.currentTimeMillis());
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: b */
    public synchronized InterfaceC2310p mo2201b(String str) {
        C2307m c2307m;
        C4195m.m4771I(!this.f5911j);
        c2307m = this.f5905d.f5875a.get(str);
        return c2307m != null ? c2307m.f5873d : C2312r.f5895a;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: c */
    public synchronized void mo2202c(String str, C2311q c2311q) {
        C4195m.m4771I(!this.f5911j);
        m2258o();
        C2308n c2308n = this.f5905d;
        C2307m m2232d = c2308n.m2232d(str);
        m2232d.f5873d = m2232d.f5873d.m2251a(c2311q);
        if (!r5.equals(r2)) {
            c2308n.f5879e.mo2239d(m2232d);
        }
        try {
            this.f5905d.m2235g();
        } catch (IOException e2) {
            throw new InterfaceC2297c.a(e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: d */
    public synchronized void mo2203d(C2305k c2305k) {
        C4195m.m4771I(!this.f5911j);
        m2260r(c2305k);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: e */
    public synchronized long mo2204e(String str, long j2, long j3) {
        C2307m c2307m;
        C4195m.m4771I(!this.f5911j);
        c2307m = this.f5905d.f5875a.get(str);
        return c2307m != null ? c2307m.m2227a(j2, j3) : -j3;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: f */
    public synchronized Set<String> mo2205f() {
        C4195m.m4771I(!this.f5911j);
        return new HashSet(this.f5905d.f5875a.keySet());
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: g */
    public synchronized void mo2206g(File file, long j2) {
        boolean z = true;
        C4195m.m4771I(!this.f5911j);
        if (file.exists()) {
            if (j2 == 0) {
                file.delete();
                return;
            }
            C2316v m2263b = C2316v.m2263b(file, j2, -9223372036854775807L, this.f5905d);
            Objects.requireNonNull(m2263b);
            C2307m m2231c = this.f5905d.m2231c(m2263b.f5863c);
            Objects.requireNonNull(m2231c);
            C4195m.m4771I(m2231c.f5874e);
            long m2248a = C2309o.m2248a(m2231c.f5873d);
            if (m2248a != -1) {
                if (m2263b.f5864e + m2263b.f5865f > m2248a) {
                    z = false;
                }
                C4195m.m4771I(z);
            }
            m2257n(m2263b);
            try {
                this.f5905d.m2235g();
                notifyAll();
            } catch (IOException e2) {
                throw new InterfaceC2297c.a(e2);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: h */
    public synchronized long mo2207h() {
        C4195m.m4771I(!this.f5911j);
        return this.f5910i;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: i */
    public synchronized C2305k mo2208i(String str, long j2) {
        C2305k mo2210k;
        C4195m.m4771I(!this.f5911j);
        m2258o();
        while (true) {
            mo2210k = mo2210k(str, j2);
            if (mo2210k == null) {
                wait();
            }
        }
        return mo2210k;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    /* renamed from: j */
    public synchronized void mo2209j(C2305k c2305k) {
        C4195m.m4771I(!this.f5911j);
        C2307m m2231c = this.f5905d.m2231c(c2305k.f5863c);
        Objects.requireNonNull(m2231c);
        C4195m.m4771I(m2231c.f5874e);
        m2231c.f5874e = false;
        this.f5905d.m2234f(m2231c.f5871b);
        notifyAll();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    @Nullable
    /* renamed from: k */
    public synchronized C2305k mo2210k(String str, long j2) {
        C2316v m2228b;
        C2316v c2316v;
        C4195m.m4771I(!this.f5911j);
        m2258o();
        C2307m c2307m = this.f5905d.f5875a.get(str);
        if (c2307m == null) {
            c2316v = new C2316v(str, j2, -1L, -9223372036854775807L, null);
        } else {
            while (true) {
                m2228b = c2307m.m2228b(j2);
                if (!m2228b.f5866g || m2228b.f5867h.length() == m2228b.f5865f) {
                    break;
                }
                m2261s();
            }
            c2316v = m2228b;
        }
        if (c2316v.f5866g) {
            return m2262t(str, c2316v);
        }
        C2307m m2232d = this.f5905d.m2232d(str);
        if (m2232d.f5874e) {
            return null;
        }
        m2232d.f5874e = true;
        return c2316v;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    @NonNull
    /* renamed from: l */
    public synchronized NavigableSet<C2305k> mo2211l(String str) {
        TreeSet treeSet;
        C4195m.m4771I(!this.f5911j);
        C2307m c2307m = this.f5905d.f5875a.get(str);
        if (c2307m != null && !c2307m.f5872c.isEmpty()) {
            treeSet = new TreeSet((Collection) c2307m.f5872c);
        }
        treeSet = new TreeSet();
        return treeSet;
    }

    /* renamed from: n */
    public final void m2257n(C2316v c2316v) {
        this.f5905d.m2232d(c2316v.f5863c).f5872c.add(c2316v);
        this.f5910i += c2316v.f5865f;
        ArrayList<InterfaceC2297c.b> arrayList = this.f5906e.get(c2316v.f5863c);
        if (arrayList != null) {
            int size = arrayList.size();
            while (true) {
                size--;
                if (size < 0) {
                    break;
                } else {
                    arrayList.get(size).mo2214c(this, c2316v);
                }
            }
        }
        ((C2313s) this.f5904c).mo2214c(this, c2316v);
    }

    /* renamed from: o */
    public synchronized void m2258o() {
        InterfaceC2297c.a aVar = this.f5912k;
        if (aVar != null) {
            throw aVar;
        }
    }

    /* renamed from: q */
    public final void m2259q(File file, boolean z, @Nullable File[] fileArr, @Nullable Map<String, C2303i> map) {
        if (fileArr == null || fileArr.length == 0) {
            if (z) {
                return;
            }
            file.delete();
            return;
        }
        for (File file2 : fileArr) {
            String name = file2.getName();
            if (z && name.indexOf(46) == -1) {
                m2259q(file2, false, file2.listFiles(), map);
            } else if (!z || (!name.startsWith("cached_content_index.exi") && !name.endsWith(".uid"))) {
                long j2 = -1;
                long j3 = -9223372036854775807L;
                C2303i remove = map != null ? map.remove(name) : null;
                if (remove != null) {
                    j2 = remove.f5861a;
                    j3 = remove.f5862b;
                }
                C2316v m2263b = C2316v.m2263b(file2, j2, j3, this.f5905d);
                if (m2263b != null) {
                    m2257n(m2263b);
                } else {
                    file2.delete();
                }
            }
        }
    }

    /* renamed from: r */
    public final void m2260r(C2305k c2305k) {
        boolean z;
        C2307m m2231c = this.f5905d.m2231c(c2305k.f5863c);
        if (m2231c != null) {
            if (m2231c.f5872c.remove(c2305k)) {
                c2305k.f5867h.delete();
                z = true;
            } else {
                z = false;
            }
            if (z) {
                this.f5910i -= c2305k.f5865f;
                this.f5905d.m2234f(m2231c.f5871b);
                ArrayList<InterfaceC2297c.b> arrayList = this.f5906e.get(c2305k.f5863c);
                if (arrayList != null) {
                    int size = arrayList.size();
                    while (true) {
                        size--;
                        if (size < 0) {
                            break;
                        } else {
                            arrayList.get(size).mo2212a(this, c2305k);
                        }
                    }
                }
                C2313s c2313s = (C2313s) this.f5904c;
                c2313s.f5898a.remove(c2305k);
                c2313s.f5899b -= c2305k.f5865f;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c
    public synchronized void release() {
        if (this.f5911j) {
            return;
        }
        this.f5906e.clear();
        m2261s();
        try {
            this.f5905d.m2235g();
            m2256u(this.f5903b);
        } catch (IOException unused) {
            m2256u(this.f5903b);
        } catch (Throwable th) {
            m2256u(this.f5903b);
            this.f5911j = true;
            throw th;
        }
        this.f5911j = true;
    }

    /* renamed from: s */
    public final void m2261s() {
        ArrayList arrayList = new ArrayList();
        Iterator<C2307m> it = this.f5905d.f5875a.values().iterator();
        while (it.hasNext()) {
            Iterator<C2316v> it2 = it.next().f5872c.iterator();
            while (it2.hasNext()) {
                C2316v next = it2.next();
                if (next.f5867h.length() != next.f5865f) {
                    arrayList.add(next);
                }
            }
        }
        for (int i2 = 0; i2 < arrayList.size(); i2++) {
            m2260r((C2305k) arrayList.get(i2));
        }
    }

    /* renamed from: t */
    public final C2316v m2262t(String str, C2316v c2316v) {
        File file;
        if (!this.f5908g) {
            return c2316v;
        }
        File file2 = c2316v.f5867h;
        Objects.requireNonNull(file2);
        file2.getName();
        long currentTimeMillis = System.currentTimeMillis();
        C2307m c2307m = this.f5905d.f5875a.get(str);
        C4195m.m4771I(c2307m.f5872c.remove(c2316v));
        File file3 = c2316v.f5867h;
        File m2264c = C2316v.m2264c(file3.getParentFile(), c2307m.f5870a, c2316v.f5864e, currentTimeMillis);
        if (file3.renameTo(m2264c)) {
            file = m2264c;
        } else {
            String str2 = "Failed to rename " + file3 + " to " + m2264c;
            file = file3;
        }
        C4195m.m4771I(c2316v.f5866g);
        C2316v c2316v2 = new C2316v(c2316v.f5863c, c2316v.f5864e, c2316v.f5865f, currentTimeMillis, file);
        c2307m.f5872c.add(c2316v2);
        ArrayList<InterfaceC2297c.b> arrayList = this.f5906e.get(c2316v.f5863c);
        if (arrayList != null) {
            int size = arrayList.size();
            while (true) {
                size--;
                if (size < 0) {
                    break;
                }
                arrayList.get(size).mo2213b(this, c2316v, c2316v2);
            }
        }
        C2313s c2313s = (C2313s) this.f5904c;
        c2313s.f5898a.remove(c2316v);
        c2313s.f5899b -= c2316v.f5865f;
        c2313s.mo2214c(this, c2316v2);
        return c2316v2;
    }
}
