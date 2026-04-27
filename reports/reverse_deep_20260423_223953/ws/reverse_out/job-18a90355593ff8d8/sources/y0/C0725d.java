package y0;

import android.util.Log;
import h2.r;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import y0.InterfaceC0723b;

/* JADX INFO: renamed from: y0.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0725d extends C0722a {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f10389e = new a(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f10390d = new ArrayList(2);

    /* JADX INFO: renamed from: y0.d$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public final synchronized void A(InterfaceC0723b interfaceC0723b) {
        t2.j.f(interfaceC0723b, "listener");
        this.f10390d.add(interfaceC0723b);
    }

    public final synchronized void D(InterfaceC0723b interfaceC0723b) {
        t2.j.f(interfaceC0723b, "listener");
        this.f10390d.remove(interfaceC0723b);
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void b(String str, Object obj) {
        t2.j.f(str, "id");
        int size = this.f10390d.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                try {
                    ((InterfaceC0723b) this.f10390d.get(i3)).b(str, obj);
                    r rVar = r.f9288a;
                } catch (Exception e3) {
                    Log.e("FwdControllerListener2", "InternalListener exception in onIntermediateImageSet", e3);
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void p(String str, Object obj, InterfaceC0723b.a aVar) {
        t2.j.f(str, "id");
        int size = this.f10390d.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                try {
                    ((InterfaceC0723b) this.f10390d.get(i3)).p(str, obj, aVar);
                    r rVar = r.f9288a;
                } catch (Exception e3) {
                    Log.e("FwdControllerListener2", "InternalListener exception in onSubmit", e3);
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void r(String str) {
        t2.j.f(str, "id");
        int size = this.f10390d.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                try {
                    ((InterfaceC0723b) this.f10390d.get(i3)).r(str);
                    r rVar = r.f9288a;
                } catch (Exception e3) {
                    Log.e("FwdControllerListener2", "InternalListener exception in onIntermediateImageFailed", e3);
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void v(String str, Object obj, InterfaceC0723b.a aVar) {
        t2.j.f(str, "id");
        int size = this.f10390d.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                try {
                    ((InterfaceC0723b) this.f10390d.get(i3)).v(str, obj, aVar);
                    r rVar = r.f9288a;
                } catch (Exception e3) {
                    Log.e("FwdControllerListener2", "InternalListener exception in onFinalImageSet", e3);
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void x(String str, InterfaceC0723b.a aVar) {
        t2.j.f(str, "id");
        int size = this.f10390d.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                try {
                    ((InterfaceC0723b) this.f10390d.get(i3)).x(str, aVar);
                    r rVar = r.f9288a;
                } catch (Exception e3) {
                    Log.e("FwdControllerListener2", "InternalListener exception in onRelease", e3);
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void y(String str, Throwable th, InterfaceC0723b.a aVar) {
        t2.j.f(str, "id");
        int size = this.f10390d.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                try {
                    ((InterfaceC0723b) this.f10390d.get(i3)).y(str, th, aVar);
                    r rVar = r.f9288a;
                } catch (Exception e3) {
                    Log.e("FwdControllerListener2", "InternalListener exception in onFailure", e3);
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }
}
