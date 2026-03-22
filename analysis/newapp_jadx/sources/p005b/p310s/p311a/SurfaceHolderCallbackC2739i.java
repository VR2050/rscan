package p005b.p310s.p311a;

import android.app.Activity;
import android.content.IntentFilter;
import android.hardware.Camera;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Message;
import android.preference.PreferenceManager;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import com.king.zxing.R$id;
import com.king.zxing.ViewfinderView;
import java.io.IOException;
import java.util.Collection;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p310s.p311a.p312o.C2745a;
import p005b.p310s.p311a.p312o.C2748d;
import p005b.p310s.p311a.p312o.C2749e;
import p005b.p310s.p311a.p312o.p313f.C2751b;

/* renamed from: b.s.a.i */
/* loaded from: classes2.dex */
public class SurfaceHolderCallbackC2739i implements SurfaceHolder.Callback {

    /* renamed from: c */
    public static final String f7459c = SurfaceHolderCallbackC2739i.class.getSimpleName();

    /* renamed from: B */
    public InterfaceC2744n f7461B;

    /* renamed from: C */
    public boolean f7462C;

    /* renamed from: e */
    public Activity f7463e;

    /* renamed from: f */
    public HandlerC2738h f7464f;

    /* renamed from: g */
    public C2731a f7465g;

    /* renamed from: h */
    public C2748d f7466h;

    /* renamed from: i */
    public C2743m f7467i;

    /* renamed from: j */
    public C2737g f7468j;

    /* renamed from: k */
    public C2736f f7469k;

    /* renamed from: l */
    public ViewfinderView f7470l;

    /* renamed from: m */
    public SurfaceHolder f7471m;

    /* renamed from: n */
    public View f7472n;

    /* renamed from: o */
    public Collection<EnumC2497a> f7473o;

    /* renamed from: r */
    public float f7476r;

    /* renamed from: w */
    public boolean f7481w;

    /* renamed from: x */
    public boolean f7482x;

    /* renamed from: q */
    public boolean f7475q = true;

    /* renamed from: s */
    public boolean f7477s = true;

    /* renamed from: t */
    public boolean f7478t = false;

    /* renamed from: u */
    public boolean f7479u = false;

    /* renamed from: v */
    public boolean f7480v = true;

    /* renamed from: y */
    public float f7483y = 0.9f;

    /* renamed from: z */
    public float f7484z = 45.0f;

    /* renamed from: A */
    public float f7460A = 100.0f;

    /* renamed from: p */
    public boolean f7474p = false;

    public SurfaceHolderCallbackC2739i(Activity activity, SurfaceView surfaceView, ViewfinderView viewfinderView, View view) {
        this.f7463e = activity;
        this.f7470l = viewfinderView;
        this.f7472n = view;
        this.f7471m = surfaceView.getHolder();
    }

    /* renamed from: a */
    public final float m3245a(MotionEvent motionEvent) {
        float x = motionEvent.getX(0) - motionEvent.getX(1);
        float y = motionEvent.getY(0) - motionEvent.getY(1);
        return (float) Math.sqrt((y * y) + (x * x));
    }

    /* renamed from: b */
    public final void m3246b(boolean z, Camera camera) {
        Camera.Parameters parameters = camera.getParameters();
        if (parameters.isZoomSupported()) {
            int maxZoom = parameters.getMaxZoom();
            int zoom = parameters.getZoom();
            if (z && zoom < maxZoom) {
                zoom++;
            } else if (zoom > 0) {
                zoom--;
            }
            parameters.setZoom(zoom);
            camera.setParameters(parameters);
        }
    }

    /* renamed from: c */
    public final void m3247c(SurfaceHolder surfaceHolder) {
        if (surfaceHolder == null) {
            throw new IllegalStateException("No SurfaceHolder provided");
        }
        if (this.f7466h.m3266c()) {
            return;
        }
        try {
            this.f7466h.m3267d(surfaceHolder);
            if (this.f7464f == null) {
                HandlerC2738h handlerC2738h = new HandlerC2738h(this.f7463e, this.f7470l, this.f7465g, this.f7473o, null, null, this.f7466h);
                this.f7464f = handlerC2738h;
                handlerC2738h.f7455i = false;
                handlerC2738h.f7456j = false;
                handlerC2738h.f7457k = this.f7477s;
                handlerC2738h.f7458l = this.f7478t;
            }
        } catch (IOException | RuntimeException unused) {
        }
    }

    /* renamed from: d */
    public void m3248d() {
        this.f7467i = new C2743m(this.f7463e);
        this.f7468j = new C2737g(this.f7463e);
        Activity activity = this.f7463e;
        this.f7469k = new C2736f(activity);
        this.f7462C = activity.getPackageManager().hasSystemFeature("android.hardware.camera.flash");
        C2748d c2748d = new C2748d(this.f7463e);
        this.f7466h = c2748d;
        c2748d.f7539k = false;
        c2748d.f7540l = this.f7483y;
        c2748d.f7541m = 0;
        c2748d.f7542n = 0;
        View view = this.f7472n;
        if (view != null && this.f7462C) {
            view.setOnClickListener(new View.OnClickListener() { // from class: b.s.a.c
                /* JADX WARN: Removed duplicated region for block: B:18:0x003c A[Catch: all -> 0x007c, TryCatch #0 {, blocks: (B:6:0x000f, B:8:0x0013, B:10:0x001d, B:12:0x0023, B:14:0x002f, B:18:0x003c, B:22:0x0044, B:23:0x004a, B:25:0x005f, B:26:0x006d, B:28:0x0071), top: B:5:0x000f }] */
                @Override // android.view.View.OnClickListener
                /*
                    Code decompiled incorrectly, please refer to instructions dump.
                    To view partially-correct add '--show-bad-code' argument
                */
                public final void onClick(android.view.View r8) {
                    /*
                        r7 = this;
                        b.s.a.i r8 = p005b.p310s.p311a.SurfaceHolderCallbackC2739i.this
                        b.s.a.o.d r0 = r8.f7466h
                        if (r0 == 0) goto L7f
                        android.view.View r8 = r8.f7472n
                        boolean r8 = r8.isSelected()
                        r1 = 1
                        r8 = r8 ^ r1
                        monitor-enter(r0)
                        b.s.a.o.f.b r2 = r0.f7531c     // Catch: java.lang.Throwable -> L7c
                        if (r2 == 0) goto L7a
                        b.s.a.o.b r3 = r0.f7530b     // Catch: java.lang.Throwable -> L7c
                        android.hardware.Camera r4 = r2.f7555b     // Catch: java.lang.Throwable -> L7c
                        java.util.Objects.requireNonNull(r3)     // Catch: java.lang.Throwable -> L7c
                        r3 = 0
                        if (r4 == 0) goto L39
                        android.hardware.Camera$Parameters r4 = r4.getParameters()     // Catch: java.lang.Throwable -> L7c
                        if (r4 == 0) goto L39
                        java.lang.String r4 = r4.getFlashMode()     // Catch: java.lang.Throwable -> L7c
                        java.lang.String r5 = "on"
                        boolean r5 = r5.equals(r4)     // Catch: java.lang.Throwable -> L7c
                        if (r5 != 0) goto L37
                        java.lang.String r5 = "torch"
                        boolean r4 = r5.equals(r4)     // Catch: java.lang.Throwable -> L7c
                        if (r4 == 0) goto L39
                    L37:
                        r4 = 1
                        goto L3a
                    L39:
                        r4 = 0
                    L3a:
                        if (r8 == r4) goto L7a
                        b.s.a.o.a r4 = r0.f7532d     // Catch: java.lang.Throwable -> L7c
                        if (r4 == 0) goto L41
                        goto L42
                    L41:
                        r1 = 0
                    L42:
                        if (r1 == 0) goto L4a
                        r4.m3258c()     // Catch: java.lang.Throwable -> L7c
                        r4 = 0
                        r0.f7532d = r4     // Catch: java.lang.Throwable -> L7c
                    L4a:
                        r0.f7546r = r8     // Catch: java.lang.Throwable -> L7c
                        b.s.a.o.b r4 = r0.f7530b     // Catch: java.lang.Throwable -> L7c
                        android.hardware.Camera r5 = r2.f7555b     // Catch: java.lang.Throwable -> L7c
                        java.util.Objects.requireNonNull(r4)     // Catch: java.lang.Throwable -> L7c
                        android.hardware.Camera$Parameters r6 = r5.getParameters()     // Catch: java.lang.Throwable -> L7c
                        r4.m3259a(r6, r8, r3)     // Catch: java.lang.Throwable -> L7c
                        r5.setParameters(r6)     // Catch: java.lang.Throwable -> L7c
                        if (r1 == 0) goto L6d
                        b.s.a.o.a r1 = new b.s.a.o.a     // Catch: java.lang.Throwable -> L7c
                        android.content.Context r3 = r0.f7529a     // Catch: java.lang.Throwable -> L7c
                        android.hardware.Camera r2 = r2.f7555b     // Catch: java.lang.Throwable -> L7c
                        r1.<init>(r3, r2)     // Catch: java.lang.Throwable -> L7c
                        r0.f7532d = r1     // Catch: java.lang.Throwable -> L7c
                        r1.m3257b()     // Catch: java.lang.Throwable -> L7c
                    L6d:
                        b.s.a.o.d$b r1 = r0.f7544p     // Catch: java.lang.Throwable -> L7c
                        if (r1 == 0) goto L7a
                        b.s.a.b r1 = (p005b.p310s.p311a.C2732b) r1     // Catch: java.lang.Throwable -> L7c
                        b.s.a.i r1 = r1.f7435a     // Catch: java.lang.Throwable -> L7c
                        android.view.View r1 = r1.f7472n     // Catch: java.lang.Throwable -> L7c
                        r1.setSelected(r8)     // Catch: java.lang.Throwable -> L7c
                    L7a:
                        monitor-exit(r0)
                        goto L7f
                    L7c:
                        r8 = move-exception
                        monitor-exit(r0)
                        throw r8
                    L7f:
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: p005b.p310s.p311a.ViewOnClickListenerC2733c.onClick(android.view.View):void");
                }
            });
            this.f7466h.setOnSensorListener(new C2735e(this));
            this.f7466h.setOnTorchListener(new C2732b(this));
        }
        this.f7465g = new C2731a(this);
        C2737g c2737g = this.f7468j;
        c2737g.f7448g = this.f7481w;
        c2737g.f7449h = this.f7482x;
        C2736f c2736f = this.f7469k;
        c2736f.f7440a = this.f7484z;
        c2736f.f7441b = this.f7460A;
    }

    /* renamed from: e */
    public void m3249e() {
        HandlerC2738h handlerC2738h = this.f7464f;
        if (handlerC2738h != null) {
            handlerC2738h.f7452f = 3;
            C2748d c2748d = handlerC2738h.f7453g;
            C2745a c2745a = c2748d.f7532d;
            if (c2745a != null) {
                c2745a.m3258c();
                c2748d.f7532d = null;
            }
            C2751b c2751b = c2748d.f7531c;
            if (c2751b != null && c2748d.f7536h) {
                c2751b.f7555b.stopPreview();
                C2749e c2749e = c2748d.f7543o;
                c2749e.f7549c = null;
                c2749e.f7550d = 0;
                c2748d.f7536h = false;
            }
            Message.obtain(handlerC2738h.f7451e.m3253a(), R$id.quit).sendToTarget();
            try {
                handlerC2738h.f7451e.join(100L);
            } catch (InterruptedException unused) {
            }
            handlerC2738h.removeMessages(R$id.decode_succeeded);
            handlerC2738h.removeMessages(R$id.decode_failed);
            this.f7464f = null;
        }
        C2743m c2743m = this.f7467i;
        c2743m.m3254a();
        if (c2743m.f7509d) {
            c2743m.f7507b.unregisterReceiver(c2743m.f7508c);
            c2743m.f7509d = false;
        }
        C2736f c2736f = this.f7469k;
        if (c2736f.f7444e != null) {
            ((SensorManager) c2736f.f7442c.getApplicationContext().getSystemService("sensor")).unregisterListener(c2736f);
            c2736f.f7443d = null;
            c2736f.f7444e = null;
        }
        this.f7468j.close();
        C2748d c2748d2 = this.f7466h;
        C2751b c2751b2 = c2748d2.f7531c;
        if (c2751b2 != null) {
            c2751b2.f7555b.release();
            c2748d2.f7531c = null;
            c2748d2.f7533e = null;
            c2748d2.f7534f = null;
        }
        if (this.f7474p) {
            return;
        }
        this.f7471m.removeCallback(this);
    }

    /* renamed from: f */
    public void m3250f() {
        this.f7468j.m3243d();
        C2743m c2743m = this.f7467i;
        if (!c2743m.f7509d) {
            c2743m.f7507b.registerReceiver(c2743m.f7508c, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
            c2743m.f7509d = true;
        }
        c2743m.m3255b();
        if (this.f7474p) {
            m3247c(this.f7471m);
        } else {
            this.f7471m.addCallback(this);
        }
        C2736f c2736f = this.f7469k;
        c2736f.f7443d = this.f7466h;
        String string = PreferenceManager.getDefaultSharedPreferences(c2736f.f7442c).getString("preferences_front_light_mode", "AUTO");
        if ((string == null ? 2 : C1345b.m353e(string)) == 2) {
            SensorManager sensorManager = (SensorManager) c2736f.f7442c.getApplicationContext().getSystemService("sensor");
            Sensor defaultSensor = sensorManager.getDefaultSensor(5);
            c2736f.f7444e = defaultSensor;
            if (defaultSensor != null) {
                sensorManager.registerListener(c2736f, defaultSensor, 3);
            }
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceChanged(SurfaceHolder surfaceHolder, int i2, int i3, int i4) {
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceCreated(SurfaceHolder surfaceHolder) {
        if (this.f7474p) {
            return;
        }
        this.f7474p = true;
        m3247c(surfaceHolder);
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceDestroyed(SurfaceHolder surfaceHolder) {
        this.f7474p = false;
    }
}
