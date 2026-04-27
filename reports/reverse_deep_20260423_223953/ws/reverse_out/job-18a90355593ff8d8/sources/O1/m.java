package O1;

import android.view.MotionEvent;
import android.view.View;
import com.facebook.react.uimanager.C0479x0;
import com.facebook.react.uimanager.InterfaceC0477w0;

/* JADX INFO: loaded from: classes.dex */
public final class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final m f2085a = new m();

    private m() {
    }

    public static final void a(View view, MotionEvent motionEvent) {
        t2.j.f(view, "view");
        t2.j.f(motionEvent, "event");
        InterfaceC0477w0 interfaceC0477w0A = C0479x0.a(view);
        if (interfaceC0477w0A != null) {
            interfaceC0477w0A.b(view, motionEvent);
        }
    }

    public static final void b(View view, MotionEvent motionEvent) {
        t2.j.f(view, "view");
        t2.j.f(motionEvent, "event");
        InterfaceC0477w0 interfaceC0477w0A = C0479x0.a(view);
        if (interfaceC0477w0A != null) {
            interfaceC0477w0A.c(view, motionEvent);
        }
    }
}
