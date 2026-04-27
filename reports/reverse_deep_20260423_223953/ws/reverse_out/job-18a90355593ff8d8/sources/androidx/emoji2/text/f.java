package androidx.emoji2.text;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.view.KeyEvent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import l.C0607b;

/* JADX INFO: loaded from: classes.dex */
public class f {

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final Object f4602o = new Object();

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final Object f4603p = new Object();

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private static volatile f f4604q;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Set f4606b;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final b f4609e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    final h f4610f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final j f4611g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    final boolean f4612h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    final boolean f4613i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    final int[] f4614j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final boolean f4615k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final int f4616l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final int f4617m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final e f4618n;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ReadWriteLock f4605a = new ReentrantReadWriteLock();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile int f4607c = 3;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Handler f4608d = new Handler(Looper.getMainLooper());

    private static final class a extends b {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private volatile androidx.emoji2.text.i f4619b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private volatile n f4620c;

        /* JADX INFO: renamed from: androidx.emoji2.text.f$a$a, reason: collision with other inner class name */
        class C0069a extends i {
            C0069a() {
            }

            @Override // androidx.emoji2.text.f.i
            public void a(Throwable th) {
                a.this.f4622a.n(th);
            }

            @Override // androidx.emoji2.text.f.i
            public void b(n nVar) {
                a.this.d(nVar);
            }
        }

        a(f fVar) {
            super(fVar);
        }

        @Override // androidx.emoji2.text.f.b
        void a() {
            try {
                this.f4622a.f4610f.a(new C0069a());
            } catch (Throwable th) {
                this.f4622a.n(th);
            }
        }

        @Override // androidx.emoji2.text.f.b
        CharSequence b(CharSequence charSequence, int i3, int i4, int i5, boolean z3) {
            return this.f4619b.h(charSequence, i3, i4, i5, z3);
        }

        @Override // androidx.emoji2.text.f.b
        void c(EditorInfo editorInfo) {
            editorInfo.extras.putInt("android.support.text.emoji.emojiCompat_metadataVersion", this.f4620c.e());
            editorInfo.extras.putBoolean("android.support.text.emoji.emojiCompat_replaceAll", this.f4622a.f4612h);
        }

        void d(n nVar) {
            if (nVar == null) {
                this.f4622a.n(new IllegalArgumentException("metadataRepo cannot be null"));
                return;
            }
            this.f4620c = nVar;
            n nVar2 = this.f4620c;
            j jVar = this.f4622a.f4611g;
            e eVar = this.f4622a.f4618n;
            f fVar = this.f4622a;
            this.f4619b = new androidx.emoji2.text.i(nVar2, jVar, eVar, fVar.f4613i, fVar.f4614j, androidx.emoji2.text.h.a());
            this.f4622a.o();
        }
    }

    private static class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final f f4622a;

        b(f fVar) {
            this.f4622a = fVar;
        }

        abstract void a();

        abstract CharSequence b(CharSequence charSequence, int i3, int i4, int i5, boolean z3);

        abstract void c(EditorInfo editorInfo);
    }

    public static abstract class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final h f4623a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        j f4624b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        boolean f4625c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        boolean f4626d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        int[] f4627e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        Set f4628f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        boolean f4629g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        int f4630h = -16711936;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        int f4631i = 0;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        e f4632j = new androidx.emoji2.text.e();

        protected c(h hVar) {
            q.g.g(hVar, "metadataLoader cannot be null.");
            this.f4623a = hVar;
        }

        protected final h a() {
            return this.f4623a;
        }

        public c b(int i3) {
            this.f4631i = i3;
            return this;
        }
    }

    public static class d implements j {
        @Override // androidx.emoji2.text.f.j
        public androidx.emoji2.text.j a(p pVar) {
            return new q(pVar);
        }
    }

    public interface e {
        boolean a(CharSequence charSequence, int i3, int i4, int i5);
    }

    /* JADX INFO: renamed from: androidx.emoji2.text.f$f, reason: collision with other inner class name */
    public static abstract class AbstractC0070f {
        public void a(Throwable th) {
        }

        public void b() {
        }
    }

    private static class g implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final List f4633b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Throwable f4634c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f4635d;

        g(AbstractC0070f abstractC0070f, int i3) {
            this(Arrays.asList((AbstractC0070f) q.g.g(abstractC0070f, "initCallback cannot be null")), i3, null);
        }

        @Override // java.lang.Runnable
        public void run() {
            int size = this.f4633b.size();
            int i3 = 0;
            if (this.f4635d != 1) {
                while (i3 < size) {
                    ((AbstractC0070f) this.f4633b.get(i3)).a(this.f4634c);
                    i3++;
                }
            } else {
                while (i3 < size) {
                    ((AbstractC0070f) this.f4633b.get(i3)).b();
                    i3++;
                }
            }
        }

        g(Collection collection, int i3) {
            this(collection, i3, null);
        }

        g(Collection collection, int i3, Throwable th) {
            q.g.g(collection, "initCallbacks cannot be null");
            this.f4633b = new ArrayList(collection);
            this.f4635d = i3;
            this.f4634c = th;
        }
    }

    public interface h {
        void a(i iVar);
    }

    public static abstract class i {
        public abstract void a(Throwable th);

        public abstract void b(n nVar);
    }

    public interface j {
        androidx.emoji2.text.j a(p pVar);
    }

    private f(c cVar) {
        this.f4612h = cVar.f4625c;
        this.f4613i = cVar.f4626d;
        this.f4614j = cVar.f4627e;
        this.f4615k = cVar.f4629g;
        this.f4616l = cVar.f4630h;
        this.f4610f = cVar.f4623a;
        this.f4617m = cVar.f4631i;
        this.f4618n = cVar.f4632j;
        C0607b c0607b = new C0607b();
        this.f4606b = c0607b;
        j jVar = cVar.f4624b;
        this.f4611g = jVar == null ? new d() : jVar;
        Set set = cVar.f4628f;
        if (set != null && !set.isEmpty()) {
            c0607b.addAll(cVar.f4628f);
        }
        this.f4609e = new a(this);
        m();
    }

    public static f c() {
        f fVar;
        synchronized (f4602o) {
            fVar = f4604q;
            q.g.h(fVar != null, "EmojiCompat is not initialized.\n\nYou must initialize EmojiCompat prior to referencing the EmojiCompat instance.\n\nThe most likely cause of this error is disabling the EmojiCompatInitializer\neither explicitly in AndroidManifest.xml, or by including\nandroidx.emoji2:emoji2-bundled.\n\nAutomatic initialization is typically performed by EmojiCompatInitializer. If\nyou are not expecting to initialize EmojiCompat manually in your application,\nplease check to ensure it has not been removed from your APK's manifest. You can\ndo this in Android Studio using Build > Analyze APK.\n\nIn the APK Analyzer, ensure that the startup entry for\nEmojiCompatInitializer and InitializationProvider is present in\n AndroidManifest.xml. If it is missing or contains tools:node=\"remove\", and you\nintend to use automatic configuration, verify:\n\n  1. Your application does not include emoji2-bundled\n  2. All modules do not contain an exclusion manifest rule for\n     EmojiCompatInitializer or InitializationProvider. For more information\n     about manifest exclusions see the documentation for the androidx startup\n     library.\n\nIf you intend to use emoji2-bundled, please call EmojiCompat.init. You can\nlearn more in the documentation for BundledEmojiCompatConfig.\n\nIf you intended to perform manual configuration, it is recommended that you call\nEmojiCompat.init immediately on application startup.\n\nIf you still cannot resolve this issue, please open a bug with your specific\nconfiguration to help improve error message.");
        }
        return fVar;
    }

    public static boolean f(InputConnection inputConnection, Editable editable, int i3, int i4, boolean z3) {
        return androidx.emoji2.text.i.b(inputConnection, editable, i3, i4, z3);
    }

    public static boolean g(Editable editable, int i3, KeyEvent keyEvent) {
        return androidx.emoji2.text.i.c(editable, i3, keyEvent);
    }

    public static f h(c cVar) {
        f fVar = f4604q;
        if (fVar == null) {
            synchronized (f4602o) {
                try {
                    fVar = f4604q;
                    if (fVar == null) {
                        fVar = new f(cVar);
                        f4604q = fVar;
                    }
                } finally {
                }
            }
        }
        return fVar;
    }

    public static boolean i() {
        return f4604q != null;
    }

    private boolean k() {
        return e() == 1;
    }

    private void m() {
        this.f4605a.writeLock().lock();
        try {
            if (this.f4617m == 0) {
                this.f4607c = 0;
            }
            this.f4605a.writeLock().unlock();
            if (e() == 0) {
                this.f4609e.a();
            }
        } catch (Throwable th) {
            this.f4605a.writeLock().unlock();
            throw th;
        }
    }

    public int d() {
        return this.f4616l;
    }

    public int e() {
        this.f4605a.readLock().lock();
        try {
            return this.f4607c;
        } finally {
            this.f4605a.readLock().unlock();
        }
    }

    public boolean j() {
        return this.f4615k;
    }

    public void l() {
        q.g.h(this.f4617m == 1, "Set metadataLoadStrategy to LOAD_STRATEGY_MANUAL to execute manual loading");
        if (k()) {
            return;
        }
        this.f4605a.writeLock().lock();
        try {
            if (this.f4607c == 0) {
                return;
            }
            this.f4607c = 0;
            this.f4605a.writeLock().unlock();
            this.f4609e.a();
        } finally {
            this.f4605a.writeLock().unlock();
        }
    }

    void n(Throwable th) {
        ArrayList arrayList = new ArrayList();
        this.f4605a.writeLock().lock();
        try {
            this.f4607c = 2;
            arrayList.addAll(this.f4606b);
            this.f4606b.clear();
            this.f4605a.writeLock().unlock();
            this.f4608d.post(new g(arrayList, this.f4607c, th));
        } catch (Throwable th2) {
            this.f4605a.writeLock().unlock();
            throw th2;
        }
    }

    void o() {
        ArrayList arrayList = new ArrayList();
        this.f4605a.writeLock().lock();
        try {
            this.f4607c = 1;
            arrayList.addAll(this.f4606b);
            this.f4606b.clear();
            this.f4605a.writeLock().unlock();
            this.f4608d.post(new g(arrayList, this.f4607c));
        } catch (Throwable th) {
            this.f4605a.writeLock().unlock();
            throw th;
        }
    }

    public CharSequence p(CharSequence charSequence) {
        return q(charSequence, 0, charSequence == null ? 0 : charSequence.length());
    }

    public CharSequence q(CharSequence charSequence, int i3, int i4) {
        return r(charSequence, i3, i4, Integer.MAX_VALUE);
    }

    public CharSequence r(CharSequence charSequence, int i3, int i4, int i5) {
        return s(charSequence, i3, i4, i5, 0);
    }

    public CharSequence s(CharSequence charSequence, int i3, int i4, int i5, int i6) {
        boolean z3;
        q.g.h(k(), "Not initialized yet");
        q.g.d(i3, "start cannot be negative");
        q.g.d(i4, "end cannot be negative");
        q.g.d(i5, "maxEmojiCount cannot be negative");
        q.g.a(i3 <= i4, "start should be <= than end");
        if (charSequence == null) {
            return null;
        }
        q.g.a(i3 <= charSequence.length(), "start should be < than charSequence length");
        q.g.a(i4 <= charSequence.length(), "end should be < than charSequence length");
        if (charSequence.length() == 0 || i3 == i4) {
            return charSequence;
        }
        if (i6 != 1) {
            z3 = i6 != 2 ? this.f4612h : false;
        } else {
            z3 = true;
        }
        return this.f4609e.b(charSequence, i3, i4, i5, z3);
    }

    public void t(AbstractC0070f abstractC0070f) {
        q.g.g(abstractC0070f, "initCallback cannot be null");
        this.f4605a.writeLock().lock();
        try {
            if (this.f4607c == 1 || this.f4607c == 2) {
                this.f4608d.post(new g(abstractC0070f, this.f4607c));
            } else {
                this.f4606b.add(abstractC0070f);
            }
            this.f4605a.writeLock().unlock();
        } catch (Throwable th) {
            this.f4605a.writeLock().unlock();
            throw th;
        }
    }

    public void u(AbstractC0070f abstractC0070f) {
        q.g.g(abstractC0070f, "initCallback cannot be null");
        this.f4605a.writeLock().lock();
        try {
            this.f4606b.remove(abstractC0070f);
        } finally {
            this.f4605a.writeLock().unlock();
        }
    }

    public void v(EditorInfo editorInfo) {
        if (!k() || editorInfo == null) {
            return;
        }
        if (editorInfo.extras == null) {
            editorInfo.extras = new Bundle();
        }
        this.f4609e.c(editorInfo);
    }
}
