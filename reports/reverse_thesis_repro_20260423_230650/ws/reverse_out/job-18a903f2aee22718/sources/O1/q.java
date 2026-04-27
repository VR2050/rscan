package O1;

import O1.s;
import android.view.MotionEvent;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.SoftAssertions;
import com.facebook.react.uimanager.events.RCTEventEmitter;
import com.facebook.react.uimanager.events.RCTModernEventEmitter;
import h2.C0562h;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class q extends d {

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    public static final a f2126m = new a(null);

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static final String f2127n = q.class.getSimpleName();

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final q.f f2128o = new q.f(3);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private MotionEvent f2129h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private s f2130i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private short f2131j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private float f2132k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private float f2133l;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final q a(int i3, int i4, s sVar, MotionEvent motionEvent, long j3, float f3, float f4, r rVar) {
            t2.j.f(rVar, "touchEventCoalescingKeyHelper");
            q qVar = (q) q.f2128o.b();
            if (qVar == null) {
                qVar = new q(null);
            }
            Object objC = Z0.a.c(motionEvent);
            t2.j.e(objC, "assertNotNull(...)");
            qVar.A(i3, i4, sVar, (MotionEvent) objC, j3, f3, f4, rVar);
            return qVar;
        }

        private a() {
        }
    }

    public /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f2134a;

        static {
            int[] iArr = new int[s.values().length];
            try {
                iArr[s.f2137d.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[s.f2138e.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[s.f2140g.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[s.f2139f.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            f2134a = iArr;
        }
    }

    public /* synthetic */ q(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void A(int i3, int i4, s sVar, MotionEvent motionEvent, long j3, float f3, float f4, r rVar) {
        super.r(i3, i4, motionEvent.getEventTime());
        short sB = 0;
        SoftAssertions.assertCondition(j3 != Long.MIN_VALUE, "Gesture start time must be initialized");
        int action = motionEvent.getAction() & 255;
        if (action == 0) {
            rVar.a(j3);
        } else if (action == 1) {
            rVar.e(j3);
        } else if (action == 2) {
            sB = rVar.b(j3);
        } else if (action == 3) {
            rVar.e(j3);
        } else if (action == 5 || action == 6) {
            rVar.d(j3);
        }
        this.f2129h = MotionEvent.obtain(motionEvent);
        this.f2130i = sVar;
        this.f2131j = sB;
        this.f2132k = f3;
        this.f2133l = f4;
    }

    public static final q B(int i3, int i4, s sVar, MotionEvent motionEvent, long j3, float f3, float f4, r rVar) {
        return f2126m.a(i3, i4, sVar, motionEvent, j3, f3, f4, rVar);
    }

    private final boolean C() {
        if (this.f2129h != null) {
            return true;
        }
        String str = f2127n;
        t2.j.e(str, "TAG");
        ReactSoftExceptionLogger.logSoftException(str, new IllegalStateException("Cannot dispatch a TouchEvent that has no MotionEvent; the TouchEvent has been recycled"));
        return false;
    }

    @Override // O1.d
    public boolean a() {
        s sVar = (s) Z0.a.c(this.f2130i);
        int i3 = sVar == null ? -1 : b.f2134a[sVar.ordinal()];
        if (i3 == 1 || i3 == 2 || i3 == 3) {
            return false;
        }
        if (i3 == 4) {
            return true;
        }
        throw new RuntimeException("Unknown touch event type: " + this.f2130i);
    }

    @Override // O1.d
    public void c(RCTEventEmitter rCTEventEmitter) {
        t2.j.f(rCTEventEmitter, "rctEventEmitter");
        if (C()) {
            t.d(rCTEventEmitter, this);
        }
    }

    @Override // O1.d
    public void d(RCTModernEventEmitter rCTModernEventEmitter) {
        t2.j.f(rCTModernEventEmitter, "rctEventEmitter");
        if (C()) {
            rCTModernEventEmitter.receiveTouches(this);
        }
    }

    @Override // O1.d
    public short g() {
        return this.f2131j;
    }

    @Override // O1.d
    public int i() {
        s sVar = this.f2130i;
        if (sVar == null) {
            return 2;
        }
        int i3 = b.f2134a[sVar.ordinal()];
        if (i3 == 1) {
            return 0;
        }
        if (i3 == 2 || i3 == 3) {
            return 1;
        }
        if (i3 == 4) {
            return 4;
        }
        throw new C0562h();
    }

    @Override // O1.d
    public String k() {
        s.a aVar = s.f2136c;
        Object objC = Z0.a.c(this.f2130i);
        t2.j.e(objC, "assertNotNull(...)");
        return aVar.a((s) objC);
    }

    @Override // O1.d
    public void t() {
        MotionEvent motionEvent = this.f2129h;
        if (motionEvent != null) {
            motionEvent.recycle();
        }
        this.f2129h = null;
        try {
            f2128o.a(this);
        } catch (IllegalStateException e3) {
            String str = f2127n;
            t2.j.e(str, "TAG");
            ReactSoftExceptionLogger.logSoftException(str, e3);
        }
    }

    public final MotionEvent w() {
        Object objC = Z0.a.c(this.f2129h);
        t2.j.e(objC, "assertNotNull(...)");
        return (MotionEvent) objC;
    }

    public final s x() {
        Object objC = Z0.a.c(this.f2130i);
        t2.j.e(objC, "assertNotNull(...)");
        return (s) objC;
    }

    public final float y() {
        return this.f2132k;
    }

    public final float z() {
        return this.f2133l;
    }

    private q() {
    }
}
