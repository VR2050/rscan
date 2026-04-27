package u0;

import android.content.Context;
import android.view.MotionEvent;
import android.view.ViewConfiguration;

/* JADX INFO: renamed from: u0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0702a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    InterfaceC0149a f10229a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final float f10230b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    boolean f10231c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    boolean f10232d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    long f10233e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    float f10234f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    float f10235g;

    /* JADX INFO: renamed from: u0.a$a, reason: collision with other inner class name */
    public interface InterfaceC0149a {
        boolean g();
    }

    public C0702a(Context context) {
        this.f10230b = ViewConfiguration.get(context).getScaledTouchSlop();
        a();
    }

    public static C0702a c(Context context) {
        return new C0702a(context);
    }

    public void a() {
        this.f10229a = null;
        e();
    }

    public boolean b() {
        return this.f10231c;
    }

    public boolean d(MotionEvent motionEvent) {
        InterfaceC0149a interfaceC0149a;
        int action = motionEvent.getAction();
        if (action == 0) {
            this.f10231c = true;
            this.f10232d = true;
            this.f10233e = motionEvent.getEventTime();
            this.f10234f = motionEvent.getX();
            this.f10235g = motionEvent.getY();
        } else if (action == 1) {
            this.f10231c = false;
            if (Math.abs(motionEvent.getX() - this.f10234f) > this.f10230b || Math.abs(motionEvent.getY() - this.f10235g) > this.f10230b) {
                this.f10232d = false;
            }
            if (this.f10232d && motionEvent.getEventTime() - this.f10233e <= ViewConfiguration.getLongPressTimeout() && (interfaceC0149a = this.f10229a) != null) {
                interfaceC0149a.g();
            }
            this.f10232d = false;
        } else if (action != 2) {
            if (action == 3) {
                this.f10231c = false;
                this.f10232d = false;
            }
        } else if (Math.abs(motionEvent.getX() - this.f10234f) > this.f10230b || Math.abs(motionEvent.getY() - this.f10235g) > this.f10230b) {
            this.f10232d = false;
        }
        return true;
    }

    public void e() {
        this.f10231c = false;
        this.f10232d = false;
    }

    public void f(InterfaceC0149a interfaceC0149a) {
        this.f10229a = interfaceC0149a;
    }
}
