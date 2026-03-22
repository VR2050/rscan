package p005b.p199l.p200a.p201a.p248o1;

import androidx.annotation.Nullable;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;

/* renamed from: b.l.a.a.o1.y */
/* loaded from: classes.dex */
public interface InterfaceC2333y extends InterfaceC2321m {

    /* renamed from: b.l.a.a.o1.y$a */
    public static abstract class a implements InterfaceC2321m.a {
        private final e defaultRequestProperties = new e();

        @Deprecated
        public final void clearAllDefaultRequestProperties() {
            e eVar = this.defaultRequestProperties;
            synchronized (eVar) {
                eVar.f6019b = null;
                eVar.f6018a.clear();
            }
        }

        @Deprecated
        public final void clearDefaultRequestProperty(String str) {
            e eVar = this.defaultRequestProperties;
            synchronized (eVar) {
                eVar.f6019b = null;
                eVar.f6018a.remove(str);
            }
        }

        public abstract InterfaceC2333y createDataSourceInternal(e eVar);

        public final e getDefaultRequestProperties() {
            return this.defaultRequestProperties;
        }

        @Deprecated
        public final void setDefaultRequestProperty(String str, String str2) {
            this.defaultRequestProperties.m2284b(str, str2);
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m.a
        public final InterfaceC2333y createDataSource() {
            return createDataSourceInternal(this.defaultRequestProperties);
        }
    }

    /* renamed from: b.l.a.a.o1.y$b */
    public static class b extends IOException {
        public b(String str, C2324p c2324p, int i2) {
            super(str);
        }

        public b(IOException iOException, C2324p c2324p, int i2) {
            super(iOException);
        }

        public b(String str, IOException iOException, C2324p c2324p, int i2) {
            super(str, iOException);
        }
    }

    /* renamed from: b.l.a.a.o1.y$c */
    public static final class c extends b {
        public c(String str, C2324p c2324p) {
            super(C1499a.m637w("Invalid content type: ", str), c2324p, 1);
        }
    }

    /* renamed from: b.l.a.a.o1.y$d */
    public static final class d extends b {

        /* renamed from: c */
        public final int f6016c;

        /* renamed from: e */
        public final Map<String, List<String>> f6017e;

        public d(int i2, @Nullable String str, Map<String, List<String>> map, C2324p c2324p) {
            super(C1499a.m626l("Response code: ", i2), c2324p, 1);
            this.f6016c = i2;
            this.f6017e = map;
        }
    }

    /* renamed from: b.l.a.a.o1.y$e */
    public static final class e {

        /* renamed from: a */
        public final Map<String, String> f6018a = new HashMap();

        /* renamed from: b */
        public Map<String, String> f6019b;

        /* renamed from: a */
        public synchronized Map<String, String> m2283a() {
            if (this.f6019b == null) {
                this.f6019b = Collections.unmodifiableMap(new HashMap(this.f6018a));
            }
            return this.f6019b;
        }

        /* renamed from: b */
        public synchronized void m2284b(String str, String str2) {
            this.f6019b = null;
            this.f6018a.put(str, str2);
        }
    }
}
