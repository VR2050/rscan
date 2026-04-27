package androidx.appcompat.view;

import android.view.View;
import android.view.animation.Interpolator;
import androidx.core.view.AbstractC0265g0;
import androidx.core.view.C0261e0;
import androidx.core.view.InterfaceC0263f0;
import java.util.ArrayList;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public class h {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Interpolator f3385c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    InterfaceC0263f0 f3386d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f3387e;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private long f3384b = -1;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final AbstractC0265g0 f3388f = new a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final ArrayList f3383a = new ArrayList();

    class a extends AbstractC0265g0 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f3389a = false;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f3390b = 0;

        a() {
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void b(View view) {
            int i3 = this.f3390b + 1;
            this.f3390b = i3;
            if (i3 == h.this.f3383a.size()) {
                InterfaceC0263f0 interfaceC0263f0 = h.this.f3386d;
                if (interfaceC0263f0 != null) {
                    interfaceC0263f0.b(null);
                }
                d();
            }
        }

        @Override // androidx.core.view.AbstractC0265g0, androidx.core.view.InterfaceC0263f0
        public void c(View view) {
            if (this.f3389a) {
                return;
            }
            this.f3389a = true;
            InterfaceC0263f0 interfaceC0263f0 = h.this.f3386d;
            if (interfaceC0263f0 != null) {
                interfaceC0263f0.c(null);
            }
        }

        void d() {
            this.f3390b = 0;
            this.f3389a = false;
            h.this.b();
        }
    }

    public void a() {
        if (this.f3387e) {
            Iterator it = this.f3383a.iterator();
            while (it.hasNext()) {
                ((C0261e0) it.next()).c();
            }
            this.f3387e = false;
        }
    }

    void b() {
        this.f3387e = false;
    }

    public h c(C0261e0 c0261e0) {
        if (!this.f3387e) {
            this.f3383a.add(c0261e0);
        }
        return this;
    }

    public h d(C0261e0 c0261e0, C0261e0 c0261e02) {
        this.f3383a.add(c0261e0);
        c0261e02.j(c0261e0.d());
        this.f3383a.add(c0261e02);
        return this;
    }

    public h e(long j3) {
        if (!this.f3387e) {
            this.f3384b = j3;
        }
        return this;
    }

    public h f(Interpolator interpolator) {
        if (!this.f3387e) {
            this.f3385c = interpolator;
        }
        return this;
    }

    public h g(InterfaceC0263f0 interfaceC0263f0) {
        if (!this.f3387e) {
            this.f3386d = interfaceC0263f0;
        }
        return this;
    }

    public void h() {
        if (this.f3387e) {
            return;
        }
        for (C0261e0 c0261e0 : this.f3383a) {
            long j3 = this.f3384b;
            if (j3 >= 0) {
                c0261e0.f(j3);
            }
            Interpolator interpolator = this.f3385c;
            if (interpolator != null) {
                c0261e0.g(interpolator);
            }
            if (this.f3386d != null) {
                c0261e0.h(this.f3388f);
            }
            c0261e0.l();
        }
        this.f3387e = true;
    }
}
