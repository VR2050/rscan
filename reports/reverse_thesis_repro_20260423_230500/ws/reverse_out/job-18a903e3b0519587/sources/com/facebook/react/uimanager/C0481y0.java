package com.facebook.react.uimanager;

import android.util.SparseArray;
import android.util.SparseBooleanArray;

/* JADX INFO: renamed from: com.facebook.react.uimanager.y0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0481y0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final SparseArray f7765a = new SparseArray();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final SparseBooleanArray f7766b = new SparseBooleanArray();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d1.i f7767c = new d1.i();

    public void a(InterfaceC0466q0 interfaceC0466q0) {
        this.f7767c.a();
        this.f7765a.put(interfaceC0466q0.H(), interfaceC0466q0);
    }

    public void b(InterfaceC0466q0 interfaceC0466q0) {
        this.f7767c.a();
        int iH = interfaceC0466q0.H();
        this.f7765a.put(iH, interfaceC0466q0);
        this.f7766b.put(iH, true);
    }

    public InterfaceC0466q0 c(int i3) {
        this.f7767c.a();
        return (InterfaceC0466q0) this.f7765a.get(i3);
    }

    public int d() {
        this.f7767c.a();
        return this.f7766b.size();
    }

    public int e(int i3) {
        this.f7767c.a();
        return this.f7766b.keyAt(i3);
    }

    public boolean f(int i3) {
        this.f7767c.a();
        return this.f7766b.get(i3);
    }

    public void g(int i3) {
        this.f7767c.a();
        if (!this.f7766b.get(i3)) {
            this.f7765a.remove(i3);
            return;
        }
        throw new P("Trying to remove root node " + i3 + " without using removeRootNode!");
    }

    public void h(int i3) {
        this.f7767c.a();
        if (i3 == -1) {
            return;
        }
        if (this.f7766b.get(i3)) {
            this.f7765a.remove(i3);
            this.f7766b.delete(i3);
        } else {
            throw new P("View with tag " + i3 + " is not registered as a root view");
        }
    }
}
