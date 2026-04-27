package l0;

import G0.k;
import I0.C0194t;
import T0.b;
import android.content.Context;
import h0.InterfaceC0547c;
import java.util.Set;
import p0.AbstractC0643b;
import v0.InterfaceC0705a;
import y0.InterfaceC0728g;

/* JADX INFO: renamed from: l0.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0618f extends AbstractC0643b {

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final C0194t f9506t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final C0620h f9507u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private X.f f9508v;

    /* JADX INFO: renamed from: l0.f$a */
    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f9509a;

        static {
            int[] iArr = new int[AbstractC0643b.c.values().length];
            f9509a = iArr;
            try {
                iArr[AbstractC0643b.c.FULL_FETCH.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f9509a[AbstractC0643b.c.DISK_CACHE.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f9509a[AbstractC0643b.c.BITMAP_MEMORY_CACHE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    public C0618f(Context context, C0620h c0620h, C0194t c0194t, Set set, Set set2) {
        super(context, set, set2);
        this.f9506t = c0194t;
        this.f9507u = c0620h;
    }

    public static b.c F(AbstractC0643b.c cVar) {
        int i3 = a.f9509a[cVar.ordinal()];
        if (i3 == 1) {
            return b.c.FULL_FETCH;
        }
        if (i3 == 2) {
            return b.c.DISK_CACHE;
        }
        if (i3 == 3) {
            return b.c.BITMAP_MEMORY_CACHE;
        }
        throw new RuntimeException("Cache level" + cVar + "is not supported. ");
    }

    private R.d G() {
        T0.b bVar = (T0.b) l();
        k kVarP = this.f9506t.p();
        if (kVarP == null || bVar == null) {
            return null;
        }
        return bVar.l() != null ? kVarP.b(bVar, d()) : kVarP.c(bVar, d());
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0643b
    /* JADX INFO: renamed from: H, reason: merged with bridge method [inline-methods] */
    public InterfaceC0547c g(InterfaceC0705a interfaceC0705a, String str, T0.b bVar, Object obj, AbstractC0643b.c cVar) {
        return this.f9506t.l(bVar, obj, F(cVar), I(interfaceC0705a), str);
    }

    protected P0.e I(InterfaceC0705a interfaceC0705a) {
        if (interfaceC0705a instanceof C0617e) {
            return ((C0617e) interfaceC0705a).q0();
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0643b
    /* JADX INFO: renamed from: J, reason: merged with bridge method [inline-methods] */
    public C0617e v() {
        if (U0.b.d()) {
            U0.b.a("PipelineDraweeControllerBuilder#obtainController");
        }
        try {
            InterfaceC0705a interfaceC0705aN = n();
            String strC = AbstractC0643b.c();
            C0617e c0617eC = interfaceC0705aN instanceof C0617e ? (C0617e) interfaceC0705aN : this.f9507u.c();
            c0617eC.s0(w(c0617eC, strC), strC, G(), d(), this.f9508v);
            c0617eC.t0(null, this);
            if (U0.b.d()) {
                U0.b.b();
            }
            return c0617eC;
        } catch (Throwable th) {
            if (U0.b.d()) {
                U0.b.b();
            }
            throw th;
        }
    }

    public C0618f K(InterfaceC0728g interfaceC0728g) {
        return (C0618f) p();
    }
}
