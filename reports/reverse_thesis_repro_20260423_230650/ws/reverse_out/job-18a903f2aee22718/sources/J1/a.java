package J1;

import android.view.MotionEvent;
import android.view.ViewGroup;
import android.view.ViewParent;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a implements b {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final C0022a f1455c = new C0022a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private volatile int f1456a = -1;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private ViewParent f1457b;

    /* JADX INFO: renamed from: J1.a$a, reason: collision with other inner class name */
    private static final class C0022a {
        public /* synthetic */ C0022a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private C0022a() {
        }
    }

    private final void c() {
        ViewParent viewParent = this.f1457b;
        if (viewParent != null) {
            viewParent.requestDisallowInterceptTouchEvent(false);
        }
        this.f1457b = null;
    }

    @Override // J1.b
    public boolean a(ViewGroup viewGroup, MotionEvent motionEvent) {
        j.f(viewGroup, "view");
        j.f(motionEvent, "event");
        int i3 = this.f1456a;
        return (i3 == -1 || motionEvent.getAction() == 1 || viewGroup.getId() != i3) ? false : true;
    }

    public final void b() {
        this.f1456a = -1;
        c();
    }

    public final void d(int i3, ViewParent viewParent) {
        this.f1456a = i3;
        c();
        if (viewParent != null) {
            viewParent.requestDisallowInterceptTouchEvent(true);
            this.f1457b = viewParent;
        }
    }
}
