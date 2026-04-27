package l0;

import I0.C0194t;
import I0.y;
import X.n;
import android.content.Context;
import java.util.Set;
import o0.AbstractC0637a;

/* JADX INFO: renamed from: l0.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0619g implements n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f9510a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0194t f9511b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0620h f9512c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Set f9513d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Set f9514e;

    public C0619g(Context context, C0614b c0614b) {
        this(context, y.l(), c0614b);
    }

    @Override // X.n
    /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
    public C0618f get() {
        return new C0618f(this.f9510a, this.f9512c, this.f9511b, this.f9513d, this.f9514e).K(null);
    }

    public C0619g(Context context, y yVar, C0614b c0614b) {
        this(context, yVar, null, null, c0614b);
    }

    public C0619g(Context context, y yVar, Set set, Set set2, C0614b c0614b) {
        this.f9510a = context;
        C0194t c0194tJ = yVar.j();
        this.f9511b = c0194tJ;
        if (c0614b != null && c0614b.d() != null) {
            this.f9512c = c0614b.d();
        } else {
            this.f9512c = new C0620h();
        }
        this.f9512c.a(context.getResources(), AbstractC0637a.b(), yVar.b(context), yVar.q(), V.f.h(), c0194tJ.o(), c0614b != null ? c0614b.a() : null, c0614b != null ? c0614b.b() : null);
        this.f9513d = set;
        this.f9514e = set2;
        if (c0614b != null) {
            c0614b.c();
        }
    }
}
