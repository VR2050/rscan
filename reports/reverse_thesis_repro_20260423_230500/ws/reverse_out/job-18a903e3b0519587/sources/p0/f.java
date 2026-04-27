package p0;

import android.graphics.drawable.Animatable;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class f implements InterfaceC0645d {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final List f9841b = new ArrayList(2);

    private synchronized void e(String str, Throwable th) {
        Log.e("FdingControllerListener", str, th);
    }

    public synchronized void a(InterfaceC0645d interfaceC0645d) {
        this.f9841b.add(interfaceC0645d);
    }

    @Override // p0.InterfaceC0645d
    public void b(String str, Object obj) {
        int size = this.f9841b.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                InterfaceC0645d interfaceC0645d = (InterfaceC0645d) this.f9841b.get(i3);
                if (interfaceC0645d != null) {
                    interfaceC0645d.b(str, obj);
                }
            } catch (Exception e3) {
                e("InternalListener exception in onIntermediateImageSet", e3);
            }
        }
    }

    @Override // p0.InterfaceC0645d
    public synchronized void c(String str) {
        int size = this.f9841b.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                InterfaceC0645d interfaceC0645d = (InterfaceC0645d) this.f9841b.get(i3);
                if (interfaceC0645d != null) {
                    interfaceC0645d.c(str);
                }
            } catch (Exception e3) {
                e("InternalListener exception in onRelease", e3);
            }
        }
    }

    public synchronized void d() {
        this.f9841b.clear();
    }

    @Override // p0.InterfaceC0645d
    public synchronized void j(String str, Object obj) {
        int size = this.f9841b.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                InterfaceC0645d interfaceC0645d = (InterfaceC0645d) this.f9841b.get(i3);
                if (interfaceC0645d != null) {
                    interfaceC0645d.j(str, obj);
                }
            } catch (Exception e3) {
                e("InternalListener exception in onSubmit", e3);
            }
        }
    }

    @Override // p0.InterfaceC0645d
    public synchronized void k(String str, Object obj, Animatable animatable) {
        int size = this.f9841b.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                InterfaceC0645d interfaceC0645d = (InterfaceC0645d) this.f9841b.get(i3);
                if (interfaceC0645d != null) {
                    interfaceC0645d.k(str, obj, animatable);
                }
            } catch (Exception e3) {
                e("InternalListener exception in onFinalImageSet", e3);
            }
        }
    }

    @Override // p0.InterfaceC0645d
    public void l(String str, Throwable th) {
        int size = this.f9841b.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                InterfaceC0645d interfaceC0645d = (InterfaceC0645d) this.f9841b.get(i3);
                if (interfaceC0645d != null) {
                    interfaceC0645d.l(str, th);
                }
            } catch (Exception e3) {
                e("InternalListener exception in onIntermediateImageFailed", e3);
            }
        }
    }

    @Override // p0.InterfaceC0645d
    public synchronized void q(String str, Throwable th) {
        int size = this.f9841b.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                InterfaceC0645d interfaceC0645d = (InterfaceC0645d) this.f9841b.get(i3);
                if (interfaceC0645d != null) {
                    interfaceC0645d.q(str, th);
                }
            } catch (Exception e3) {
                e("InternalListener exception in onFailure", e3);
            }
        }
    }
}
