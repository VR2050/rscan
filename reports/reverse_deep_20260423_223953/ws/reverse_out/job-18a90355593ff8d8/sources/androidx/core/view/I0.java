package androidx.core.view;

import android.os.Build;
import android.view.View;
import android.view.Window;
import android.view.WindowInsetsController;
import l.C0612g;

/* JADX INFO: loaded from: classes.dex */
public final class I0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final e f4399a;

    private static class a extends e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        protected final Window f4400a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final J f4401b;

        a(Window window, J j3) {
            this.f4400a = window;
            this.f4401b = j3;
        }

        private void f(int i3) {
            if (i3 == 1) {
                g(4);
            } else if (i3 == 2) {
                g(2);
            } else {
                if (i3 != 8) {
                    return;
                }
                this.f4401b.a();
            }
        }

        private void i(int i3) {
            if (i3 == 1) {
                j(4);
                k(1024);
            } else if (i3 == 2) {
                j(2);
            } else {
                if (i3 != 8) {
                    return;
                }
                this.f4401b.b();
            }
        }

        @Override // androidx.core.view.I0.e
        void a(int i3) {
            for (int i4 = 1; i4 <= 256; i4 <<= 1) {
                if ((i3 & i4) != 0) {
                    f(i4);
                }
            }
        }

        @Override // androidx.core.view.I0.e
        void e(int i3) {
            for (int i4 = 1; i4 <= 256; i4 <<= 1) {
                if ((i3 & i4) != 0) {
                    i(i4);
                }
            }
        }

        protected void g(int i3) {
            View decorView = this.f4400a.getDecorView();
            decorView.setSystemUiVisibility(i3 | decorView.getSystemUiVisibility());
        }

        protected void h(int i3) {
            this.f4400a.addFlags(i3);
        }

        protected void j(int i3) {
            View decorView = this.f4400a.getDecorView();
            decorView.setSystemUiVisibility((~i3) & decorView.getSystemUiVisibility());
        }

        protected void k(int i3) {
            this.f4400a.clearFlags(i3);
        }
    }

    private static class b extends a {
        b(Window window, J j3) {
            super(window, j3);
        }

        @Override // androidx.core.view.I0.e
        public boolean b() {
            return (this.f4400a.getDecorView().getSystemUiVisibility() & 8192) != 0;
        }

        @Override // androidx.core.view.I0.e
        public void d(boolean z3) {
            if (!z3) {
                j(8192);
                return;
            }
            k(67108864);
            h(Integer.MIN_VALUE);
            g(8192);
        }
    }

    private static class c extends b {
        c(Window window, J j3) {
            super(window, j3);
        }

        @Override // androidx.core.view.I0.e
        public void c(boolean z3) {
            if (!z3) {
                j(16);
                return;
            }
            k(134217728);
            h(Integer.MIN_VALUE);
            g(16);
        }
    }

    private static class e {
        e() {
        }

        abstract void a(int i3);

        public abstract boolean b();

        public void c(boolean z3) {
        }

        public abstract void d(boolean z3);

        abstract void e(int i3);
    }

    public I0(Window window, View view) {
        J j3 = new J(view);
        int i3 = Build.VERSION.SDK_INT;
        if (i3 >= 30) {
            this.f4399a = new d(window, this, j3);
        } else if (i3 >= 26) {
            this.f4399a = new c(window, j3);
        } else {
            this.f4399a = new b(window, j3);
        }
    }

    public void a(int i3) {
        this.f4399a.a(i3);
    }

    public boolean b() {
        return this.f4399a.b();
    }

    public void c(boolean z3) {
        this.f4399a.c(z3);
    }

    public void d(boolean z3) {
        this.f4399a.d(z3);
    }

    public void e(int i3) {
        this.f4399a.e(i3);
    }

    private static class d extends e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final I0 f4402a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final WindowInsetsController f4403b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final J f4404c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final C0612g f4405d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        protected Window f4406e;

        d(Window window, I0 i02, J j3) {
            this(window.getInsetsController(), i02, j3);
            this.f4406e = window;
        }

        @Override // androidx.core.view.I0.e
        void a(int i3) {
            if ((i3 & 8) != 0) {
                this.f4404c.a();
            }
            this.f4403b.hide(i3 & (-9));
        }

        @Override // androidx.core.view.I0.e
        public boolean b() {
            this.f4403b.setSystemBarsAppearance(0, 0);
            return (this.f4403b.getSystemBarsAppearance() & 8) != 0;
        }

        @Override // androidx.core.view.I0.e
        public void c(boolean z3) {
            if (z3) {
                if (this.f4406e != null) {
                    f(16);
                }
                this.f4403b.setSystemBarsAppearance(16, 16);
            } else {
                if (this.f4406e != null) {
                    g(16);
                }
                this.f4403b.setSystemBarsAppearance(0, 16);
            }
        }

        @Override // androidx.core.view.I0.e
        public void d(boolean z3) {
            if (z3) {
                if (this.f4406e != null) {
                    f(8192);
                }
                this.f4403b.setSystemBarsAppearance(8, 8);
            } else {
                if (this.f4406e != null) {
                    g(8192);
                }
                this.f4403b.setSystemBarsAppearance(0, 8);
            }
        }

        @Override // androidx.core.view.I0.e
        void e(int i3) {
            if ((i3 & 8) != 0) {
                this.f4404c.b();
            }
            this.f4403b.show(i3 & (-9));
        }

        protected void f(int i3) {
            View decorView = this.f4406e.getDecorView();
            decorView.setSystemUiVisibility(i3 | decorView.getSystemUiVisibility());
        }

        protected void g(int i3) {
            View decorView = this.f4406e.getDecorView();
            decorView.setSystemUiVisibility((~i3) & decorView.getSystemUiVisibility());
        }

        d(WindowInsetsController windowInsetsController, I0 i02, J j3) {
            this.f4405d = new C0612g();
            this.f4403b = windowInsetsController;
            this.f4402a = i02;
            this.f4404c = j3;
        }
    }
}
