package androidx.core.view;

import android.content.Context;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.ViewConfiguration;

/* JADX INFO: renamed from: androidx.core.view.o, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0278o {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f4503a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0279p f4504b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final b f4505c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final a f4506d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private VelocityTracker f4507e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float f4508f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f4509g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f4510h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f4511i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int[] f4512j;

    /* JADX INFO: renamed from: androidx.core.view.o$a */
    interface a {
        float a(VelocityTracker velocityTracker, MotionEvent motionEvent, int i3);
    }

    /* JADX INFO: renamed from: androidx.core.view.o$b */
    interface b {
        void a(Context context, int[] iArr, MotionEvent motionEvent, int i3);
    }

    public C0278o(Context context, InterfaceC0279p interfaceC0279p) {
        this(context, interfaceC0279p, new b() { // from class: androidx.core.view.m
            @Override // androidx.core.view.C0278o.b
            public final void a(Context context2, int[] iArr, MotionEvent motionEvent, int i3) {
                C0278o.c(context2, iArr, motionEvent, i3);
            }
        }, new a() { // from class: androidx.core.view.n
            @Override // androidx.core.view.C0278o.a
            public final float a(VelocityTracker velocityTracker, MotionEvent motionEvent, int i3) {
                return C0278o.f(velocityTracker, motionEvent, i3);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void c(Context context, int[] iArr, MotionEvent motionEvent, int i3) {
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        iArr[0] = Z.g(context, viewConfiguration, motionEvent.getDeviceId(), i3, motionEvent.getSource());
        iArr[1] = Z.f(context, viewConfiguration, motionEvent.getDeviceId(), i3, motionEvent.getSource());
    }

    private boolean d(MotionEvent motionEvent, int i3) {
        int source = motionEvent.getSource();
        int deviceId = motionEvent.getDeviceId();
        if (this.f4510h == source && this.f4511i == deviceId && this.f4509g == i3) {
            return false;
        }
        this.f4505c.a(this.f4503a, this.f4512j, motionEvent, i3);
        this.f4510h = source;
        this.f4511i = deviceId;
        this.f4509g = i3;
        return true;
    }

    private float e(MotionEvent motionEvent, int i3) {
        if (this.f4507e == null) {
            this.f4507e = VelocityTracker.obtain();
        }
        return this.f4506d.a(this.f4507e, motionEvent, i3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static float f(VelocityTracker velocityTracker, MotionEvent motionEvent, int i3) {
        S.a(velocityTracker, motionEvent);
        S.b(velocityTracker, 1000);
        return S.d(velocityTracker, i3);
    }

    public void g(MotionEvent motionEvent, int i3) {
        boolean zD = d(motionEvent, i3);
        if (this.f4512j[0] == Integer.MAX_VALUE) {
            VelocityTracker velocityTracker = this.f4507e;
            if (velocityTracker != null) {
                velocityTracker.recycle();
                this.f4507e = null;
                return;
            }
            return;
        }
        float fE = e(motionEvent, i3) * this.f4504b.b();
        float fSignum = Math.signum(fE);
        if (zD || (fSignum != Math.signum(this.f4508f) && fSignum != 0.0f)) {
            this.f4504b.c();
        }
        float fAbs = Math.abs(fE);
        int[] iArr = this.f4512j;
        if (fAbs < iArr[0]) {
            return;
        }
        float fMax = Math.max(-r6, Math.min(fE, iArr[1]));
        this.f4508f = this.f4504b.a(fMax) ? fMax : 0.0f;
    }

    C0278o(Context context, InterfaceC0279p interfaceC0279p, b bVar, a aVar) {
        this.f4509g = -1;
        this.f4510h = -1;
        this.f4511i = -1;
        this.f4512j = new int[]{Integer.MAX_VALUE, 0};
        this.f4503a = context;
        this.f4504b = interfaceC0279p;
        this.f4505c = bVar;
        this.f4506d = aVar;
    }
}
