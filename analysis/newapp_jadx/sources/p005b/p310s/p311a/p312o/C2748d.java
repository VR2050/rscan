package p005b.p310s.p311a.p312o;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Handler;
import java.util.Objects;
import p005b.p199l.p266d.C2530l;
import p005b.p310s.p311a.C2735e;
import p005b.p310s.p311a.SurfaceHolderCallbackC2739i;
import p005b.p310s.p311a.p312o.p313f.C2751b;

/* renamed from: b.s.a.o.d */
/* loaded from: classes2.dex */
public final class C2748d {

    /* renamed from: a */
    public final Context f7529a;

    /* renamed from: b */
    public final C2746b f7530b;

    /* renamed from: c */
    public C2751b f7531c;

    /* renamed from: d */
    public C2745a f7532d;

    /* renamed from: e */
    public Rect f7533e;

    /* renamed from: f */
    public Rect f7534f;

    /* renamed from: g */
    public boolean f7535g;

    /* renamed from: h */
    public boolean f7536h;

    /* renamed from: i */
    public int f7537i;

    /* renamed from: j */
    public int f7538j;

    /* renamed from: k */
    public boolean f7539k;

    /* renamed from: l */
    public float f7540l;

    /* renamed from: m */
    public int f7541m;

    /* renamed from: n */
    public int f7542n;

    /* renamed from: o */
    public final C2749e f7543o;

    /* renamed from: p */
    public b f7544p;

    /* renamed from: q */
    public a f7545q;

    /* renamed from: r */
    public boolean f7546r;

    /* renamed from: b.s.a.o.d$a */
    public interface a {
    }

    /* renamed from: b.s.a.o.d$b */
    public interface b {
    }

    public C2748d(Context context) {
        this.f7529a = context.getApplicationContext();
        C2746b c2746b = new C2746b(context);
        this.f7530b = c2746b;
        this.f7543o = new C2749e(c2746b);
    }

    /* renamed from: a */
    public C2530l m3264a(byte[] bArr, int i2, int i3) {
        Rect rect;
        synchronized (this) {
            if (this.f7534f == null) {
                Rect m3265b = m3265b();
                if (m3265b != null) {
                    Rect rect2 = new Rect(m3265b);
                    C2746b c2746b = this.f7530b;
                    Point point = c2746b.f7525e;
                    Point point2 = c2746b.f7524d;
                    if (point != null && point2 != null) {
                        int i4 = rect2.left;
                        int i5 = point.y;
                        int i6 = point2.x;
                        rect2.left = (i4 * i5) / i6;
                        rect2.right = (rect2.right * i5) / i6;
                        int i7 = rect2.top;
                        int i8 = point.x;
                        int i9 = point2.y;
                        rect2.top = (i7 * i8) / i9;
                        rect2.bottom = (rect2.bottom * i8) / i9;
                        this.f7534f = rect2;
                    }
                }
                rect = null;
            }
            rect = this.f7534f;
        }
        if (rect == null) {
            return null;
        }
        if (this.f7539k) {
            return new C2530l(bArr, i2, i3, 0, 0, i2, i3, false);
        }
        int min = (int) (Math.min(i2, i3) * this.f7540l);
        return new C2530l(bArr, i2, i3, ((i2 - min) / 2) + this.f7542n, ((i3 - min) / 2) + this.f7541m, min, min, false);
    }

    /* renamed from: b */
    public synchronized Rect m3265b() {
        if (this.f7533e == null) {
            if (this.f7531c == null) {
                return null;
            }
            Point point = this.f7530b.f7525e;
            if (point == null) {
                return null;
            }
            int i2 = point.x;
            int i3 = point.y;
            if (this.f7539k) {
                this.f7533e = new Rect(0, 0, i2, i3);
            } else {
                int min = (int) (Math.min(i2, i3) * this.f7540l);
                int i4 = ((i2 - min) / 2) + this.f7542n;
                int i5 = ((i3 - min) / 2) + this.f7541m;
                this.f7533e = new Rect(i4, i5, i4 + min, min + i5);
            }
        }
        return this.f7533e;
    }

    /* renamed from: c */
    public synchronized boolean m3266c() {
        return this.f7531c != null;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x006b  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m3267d(android.view.SurfaceHolder r13) {
        /*
            Method dump skipped, instructions count: 463
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p310s.p311a.p312o.C2748d.m3267d(android.view.SurfaceHolder):void");
    }

    /* renamed from: e */
    public synchronized void m3268e(Handler handler, int i2) {
        C2751b c2751b = this.f7531c;
        if (c2751b != null && this.f7536h) {
            C2749e c2749e = this.f7543o;
            c2749e.f7549c = handler;
            c2749e.f7550d = i2;
            c2751b.f7555b.setOneShotPreviewCallback(c2749e);
        }
    }

    /* renamed from: f */
    public void m3269f(boolean z, float f2) {
        a aVar = this.f7545q;
        if (aVar != null) {
            boolean z2 = this.f7546r;
            SurfaceHolderCallbackC2739i surfaceHolderCallbackC2739i = ((C2735e) aVar).f7439a;
            Objects.requireNonNull(surfaceHolderCallbackC2739i);
            if (z) {
                if (surfaceHolderCallbackC2739i.f7472n.getVisibility() != 0) {
                    surfaceHolderCallbackC2739i.f7472n.setVisibility(0);
                }
            } else {
                if (z2 || surfaceHolderCallbackC2739i.f7472n.getVisibility() != 0) {
                    return;
                }
                surfaceHolderCallbackC2739i.f7472n.setVisibility(4);
            }
        }
    }

    public void setOnSensorListener(a aVar) {
        this.f7545q = aVar;
    }

    public void setOnTorchListener(b bVar) {
        this.f7544p = bVar;
    }
}
