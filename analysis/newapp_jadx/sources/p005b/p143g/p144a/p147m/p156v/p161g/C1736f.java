package p005b.p143g.p144a.p147m.p156v.p161g;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;
import p005b.p143g.p144a.p146l.InterfaceC1564a;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p166q.p167i.AbstractC1784c;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1793b;
import p005b.p143g.p144a.p169r.C1798d;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.v.g.f */
/* loaded from: classes.dex */
public class C1736f {

    /* renamed from: a */
    public final InterfaceC1564a f2567a;

    /* renamed from: b */
    public final Handler f2568b;

    /* renamed from: c */
    public final List<b> f2569c;

    /* renamed from: d */
    public final ComponentCallbacks2C1559i f2570d;

    /* renamed from: e */
    public final InterfaceC1614d f2571e;

    /* renamed from: f */
    public boolean f2572f;

    /* renamed from: g */
    public boolean f2573g;

    /* renamed from: h */
    public C1558h<Bitmap> f2574h;

    /* renamed from: i */
    public a f2575i;

    /* renamed from: j */
    public boolean f2576j;

    /* renamed from: k */
    public a f2577k;

    /* renamed from: l */
    public Bitmap f2578l;

    /* renamed from: m */
    public InterfaceC1586r<Bitmap> f2579m;

    /* renamed from: n */
    public a f2580n;

    /* renamed from: o */
    @Nullable
    public d f2581o;

    /* renamed from: p */
    public int f2582p;

    /* renamed from: q */
    public int f2583q;

    /* renamed from: r */
    public int f2584r;

    @VisibleForTesting
    /* renamed from: b.g.a.m.v.g.f$a */
    public static class a extends AbstractC1784c<Bitmap> {

        /* renamed from: c */
        public final Handler f2585c;

        /* renamed from: e */
        public final int f2586e;

        /* renamed from: f */
        public final long f2587f;

        /* renamed from: g */
        public Bitmap f2588g;

        public a(Handler handler, int i2, long j2) {
            this.f2585c = handler;
            this.f2586e = i2;
            this.f2587f = j2;
        }

        @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onLoadCleared(@Nullable Drawable drawable) {
            this.f2588g = null;
        }

        @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onResourceReady(@NonNull Object obj, @Nullable InterfaceC1793b interfaceC1793b) {
            this.f2588g = (Bitmap) obj;
            this.f2585c.sendMessageAtTime(this.f2585c.obtainMessage(1, this), this.f2587f);
        }
    }

    /* renamed from: b.g.a.m.v.g.f$b */
    public interface b {
        /* renamed from: a */
        void mo1035a();
    }

    /* renamed from: b.g.a.m.v.g.f$c */
    public class c implements Handler.Callback {
        public c() {
        }

        @Override // android.os.Handler.Callback
        public boolean handleMessage(Message message) {
            int i2 = message.what;
            if (i2 == 1) {
                C1736f.this.m1033b((a) message.obj);
                return true;
            }
            if (i2 != 2) {
                return false;
            }
            C1736f.this.f2570d.m772e((a) message.obj);
            return false;
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.v.g.f$d */
    public interface d {
        /* renamed from: a */
        void m1036a();
    }

    public C1736f(ComponentCallbacks2C1553c componentCallbacks2C1553c, InterfaceC1564a interfaceC1564a, int i2, int i3, InterfaceC1586r<Bitmap> interfaceC1586r, Bitmap bitmap) {
        InterfaceC1614d interfaceC1614d = componentCallbacks2C1553c.f1811g;
        ComponentCallbacks2C1559i m738h = ComponentCallbacks2C1553c.m738h(componentCallbacks2C1553c.f1813i.getBaseContext());
        C1558h<Bitmap> mo766a = ComponentCallbacks2C1553c.m738h(componentCallbacks2C1553c.f1813i.getBaseContext()).mo769b().mo766a(C1779f.m1110L(AbstractC1643k.f2223b).mo1081K(true).mo1075E(true).mo1097x(i2, i3));
        this.f2569c = new ArrayList();
        this.f2570d = m738h;
        Handler handler = new Handler(Looper.getMainLooper(), new c());
        this.f2571e = interfaceC1614d;
        this.f2568b = handler;
        this.f2574h = mo766a;
        this.f2567a = interfaceC1564a;
        m1034c(interfaceC1586r, bitmap);
    }

    /* renamed from: a */
    public final void m1032a() {
        if (!this.f2572f || this.f2573g) {
            return;
        }
        a aVar = this.f2580n;
        if (aVar != null) {
            this.f2580n = null;
            m1033b(aVar);
            return;
        }
        this.f2573g = true;
        long uptimeMillis = SystemClock.uptimeMillis() + this.f2567a.mo807d();
        this.f2567a.mo805b();
        this.f2577k = new a(this.f2568b, this.f2567a.mo809f(), uptimeMillis);
        this.f2574h.mo766a(new C1779f().mo1073C(new C1798d(Double.valueOf(Math.random())))).mo762W(this.f2567a).m755P(this.f2577k);
    }

    @VisibleForTesting
    /* renamed from: b */
    public void m1033b(a aVar) {
        d dVar = this.f2581o;
        if (dVar != null) {
            dVar.m1036a();
        }
        this.f2573g = false;
        if (this.f2576j) {
            this.f2568b.obtainMessage(2, aVar).sendToTarget();
            return;
        }
        if (!this.f2572f) {
            this.f2580n = aVar;
            return;
        }
        if (aVar.f2588g != null) {
            Bitmap bitmap = this.f2578l;
            if (bitmap != null) {
                this.f2571e.mo870d(bitmap);
                this.f2578l = null;
            }
            a aVar2 = this.f2575i;
            this.f2575i = aVar;
            int size = this.f2569c.size();
            while (true) {
                size--;
                if (size < 0) {
                    break;
                } else {
                    this.f2569c.get(size).mo1035a();
                }
            }
            if (aVar2 != null) {
                this.f2568b.obtainMessage(2, aVar2).sendToTarget();
            }
        }
        m1032a();
    }

    /* renamed from: c */
    public void m1034c(InterfaceC1586r<Bitmap> interfaceC1586r, Bitmap bitmap) {
        Objects.requireNonNull(interfaceC1586r, "Argument must not be null");
        this.f2579m = interfaceC1586r;
        Objects.requireNonNull(bitmap, "Argument must not be null");
        this.f2578l = bitmap;
        this.f2574h = this.f2574h.mo766a(new C1779f().m1077G(interfaceC1586r, true));
        this.f2582p = C1807i.m1147d(bitmap);
        this.f2583q = bitmap.getWidth();
        this.f2584r = bitmap.getHeight();
    }

    @VisibleForTesting
    public void setOnEveryFrameReadyListener(@Nullable d dVar) {
        this.f2581o = dVar;
    }
}
