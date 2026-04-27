package F0;

import I0.C0176a;
import Q0.i;
import Y0.e;
import android.graphics.Bitmap;
import b0.AbstractC0311a;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a extends b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final i f734a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0176a f735b;

    public a(i iVar, C0176a c0176a) {
        j.f(iVar, "bitmapPool");
        j.f(c0176a, "closeableReferenceFactory");
        this.f734a = iVar;
        this.f735b = c0176a;
    }

    @Override // F0.b
    public AbstractC0311a d(int i3, int i4, Bitmap.Config config) {
        j.f(config, "bitmapConfig");
        Bitmap bitmap = (Bitmap) this.f734a.get(e.i(i3, i4, config));
        if (bitmap.getAllocationByteCount() < i3 * i4 * e.h(config)) {
            throw new IllegalStateException("Check failed.");
        }
        bitmap.reconfigure(i3, i4, config);
        AbstractC0311a abstractC0311aC = this.f735b.c(bitmap, this.f734a);
        j.e(abstractC0311aC, "create(...)");
        return abstractC0311aC;
    }
}
