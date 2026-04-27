package com.facebook.react.views.image;

import D1.b;
import I0.EnumC0189n;
import N0.l;
import Q1.n;
import T0.b;
import W1.a;
import W1.b;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.Shader;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import b0.AbstractC0311a;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.react.views.image.b;
import f1.C0527a;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import l0.AbstractC0616d;
import p0.AbstractC0643b;
import p0.InterfaceC0645d;
import q1.C0655b;
import s0.RunnableC0682b;
import s0.q;
import t0.C0690a;
import t0.C0691b;
import t0.C0693d;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class h extends w0.d {

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    public static final a f7808C = new a(null);

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private static final Matrix f7809D = new Matrix();

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private float f7810A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private com.facebook.react.views.image.c f7811B;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final AbstractC0643b f7812i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private Object f7813j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final List f7814k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private W1.a f7815l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private W1.a f7816m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private Drawable f7817n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private Drawable f7818o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f7819p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private q f7820q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private Shader.TileMode f7821r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f7822s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private b f7823t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private S0.a f7824u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private g f7825v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private InterfaceC0645d f7826w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private int f7827x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private boolean f7828y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private ReadableMap f7829z;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final C0690a b(Context context) {
            C0691b c0691b = new C0691b(context.getResources());
            C0693d c0693dA = C0693d.a(0.0f);
            c0693dA.o(true);
            C0690a c0690aA = c0691b.u(c0693dA).a();
            j.e(c0690aA, "build(...)");
            return c0690aA;
        }

        private a() {
        }
    }

    private final class b extends T0.a {
        public b() {
        }

        @Override // T0.a, T0.d
        public AbstractC0311a a(Bitmap bitmap, F0.b bVar) {
            j.f(bitmap, "source");
            j.f(bVar, "bitmapFactory");
            Rect rect = new Rect(0, 0, h.this.getWidth(), h.this.getHeight());
            h.this.f7820q.a(h.f7809D, rect, bitmap.getWidth(), bitmap.getHeight(), 0.0f, 0.0f);
            Paint paint = new Paint();
            paint.setAntiAlias(true);
            BitmapShader bitmapShader = new BitmapShader(bitmap, h.this.f7821r, h.this.f7821r);
            bitmapShader.setLocalMatrix(h.f7809D);
            paint.setShader(bitmapShader);
            AbstractC0311a abstractC0311aA = bVar.a(h.this.getWidth(), h.this.getHeight());
            j.e(abstractC0311aA, "createBitmap(...)");
            try {
                new Canvas((Bitmap) abstractC0311aA.P()).drawRect(rect, paint);
                AbstractC0311a abstractC0311aClone = abstractC0311aA.clone();
                j.e(abstractC0311aClone, "clone(...)");
                return abstractC0311aClone;
            } finally {
                AbstractC0311a.D(abstractC0311aA);
            }
        }
    }

    public /* synthetic */ class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f7831a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final /* synthetic */ int[] f7832b;

        static {
            int[] iArr = new int[D1.a.values().length];
            try {
                iArr[D1.a.f596e.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            f7831a = iArr;
            int[] iArr2 = new int[com.facebook.react.views.image.c.values().length];
            try {
                iArr2[com.facebook.react.views.image.c.f7798b.ordinal()] = 1;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr2[com.facebook.react.views.image.c.f7799c.ordinal()] = 2;
            } catch (NoSuchFieldError unused3) {
            }
            f7832b = iArr2;
        }
    }

    public static final class d extends g {

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ EventDispatcher f7833g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ h f7834h;

        d(EventDispatcher eventDispatcher, h hVar) {
            this.f7833g = eventDispatcher;
            this.f7834h = hVar;
        }

        @Override // p0.InterfaceC0645d
        public void j(String str, Object obj) {
            j.f(str, "id");
            EventDispatcher eventDispatcher = this.f7833g;
            if (eventDispatcher == null) {
                return;
            }
            eventDispatcher.g(com.facebook.react.views.image.b.f7790o.d(H0.f(this.f7834h), this.f7834h.getId()));
        }

        @Override // p0.InterfaceC0645d
        public void q(String str, Throwable th) {
            j.f(str, "id");
            j.f(th, "throwable");
            EventDispatcher eventDispatcher = this.f7833g;
            if (eventDispatcher == null) {
                return;
            }
            eventDispatcher.g(com.facebook.react.views.image.b.f7790o.a(H0.f(this.f7834h), this.f7834h.getId(), th));
        }

        @Override // com.facebook.react.views.image.g
        public void x(int i3, int i4) {
            if (this.f7833g == null || this.f7834h.getImageSource$ReactAndroid_release() == null) {
                return;
            }
            EventDispatcher eventDispatcher = this.f7833g;
            b.a aVar = com.facebook.react.views.image.b.f7790o;
            int iF = H0.f(this.f7834h);
            int id = this.f7834h.getId();
            W1.a imageSource$ReactAndroid_release = this.f7834h.getImageSource$ReactAndroid_release();
            eventDispatcher.g(aVar.e(iF, id, imageSource$ReactAndroid_release != null ? imageSource$ReactAndroid_release.e() : null, i3, i4));
        }

        @Override // p0.InterfaceC0645d
        /* JADX INFO: renamed from: y, reason: merged with bridge method [inline-methods] */
        public void k(String str, l lVar, Animatable animatable) {
            EventDispatcher eventDispatcher;
            j.f(str, "id");
            if (lVar == null || this.f7834h.getImageSource$ReactAndroid_release() == null || (eventDispatcher = this.f7833g) == null) {
                return;
            }
            b.a aVar = com.facebook.react.views.image.b.f7790o;
            int iF = H0.f(this.f7834h);
            int id = this.f7834h.getId();
            W1.a imageSource$ReactAndroid_release = this.f7834h.getImageSource$ReactAndroid_release();
            eventDispatcher.g(aVar.c(iF, id, imageSource$ReactAndroid_release != null ? imageSource$ReactAndroid_release.e() : null, lVar.h(), lVar.d()));
            this.f7833g.g(aVar.b(H0.f(this.f7834h), this.f7834h.getId()));
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(Context context, AbstractC0643b abstractC0643b, com.facebook.react.views.image.a aVar, Object obj) {
        super(context, f7808C.b(context));
        j.f(context, "context");
        j.f(abstractC0643b, "draweeControllerBuilder");
        this.f7812i = abstractC0643b;
        this.f7813j = obj;
        this.f7814k = new ArrayList();
        this.f7820q = com.facebook.react.views.image.d.b();
        this.f7821r = com.facebook.react.views.image.d.a();
        this.f7827x = -1;
        this.f7810A = 1.0f;
        this.f7811B = com.facebook.react.views.image.c.f7798b;
        setLegacyVisibilityHandlingEnabled(true);
    }

    private final H0.g getResizeOptions() {
        int iRound = Math.round(getWidth() * this.f7810A);
        int iRound2 = Math.round(getHeight() * this.f7810A);
        if (iRound <= 0 || iRound2 <= 0) {
            return null;
        }
        return new H0.g(iRound, iRound2, 0.0f, 0.0f, 12, null);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:7:0x0010, code lost:
    
        if (r2.equals("default") == false) goto L19;
     */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final D1.a j(java.lang.String r2) {
        /*
            r1 = this;
            if (r2 == 0) goto L39
            int r0 = r2.hashCode()
            switch(r0) {
                case -1564134880: goto L2b;
                case -934641255: goto L1f;
                case 706834161: goto L13;
                case 1544803905: goto La;
                default: goto L9;
            }
        L9:
            goto L33
        La:
            java.lang.String r0 = "default"
            boolean r2 = r2.equals(r0)
            if (r2 != 0) goto L39
            goto L33
        L13:
            java.lang.String r0 = "only-if-cached"
            boolean r2 = r2.equals(r0)
            if (r2 != 0) goto L1c
            goto L33
        L1c:
            D1.a r2 = D1.a.f596e
            goto L3b
        L1f:
            java.lang.String r0 = "reload"
            boolean r2 = r2.equals(r0)
            if (r2 != 0) goto L28
            goto L33
        L28:
            D1.a r2 = D1.a.f594c
            goto L3b
        L2b:
            java.lang.String r0 = "force-cache"
            boolean r2 = r2.equals(r0)
            if (r2 != 0) goto L36
        L33:
            D1.a r2 = D1.a.f593b
            goto L3b
        L36:
            D1.a r2 = D1.a.f595d
            goto L3b
        L39:
            D1.a r2 = D1.a.f593b
        L3b:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.views.image.h.j(java.lang.String):D1.a");
    }

    private final b.c k(D1.a aVar) {
        return c.f7831a[aVar.ordinal()] == 1 ? b.c.DISK_CACHE : b.c.FULL_FETCH;
    }

    private final boolean l() {
        return this.f7814k.size() > 1;
    }

    private final boolean m() {
        return this.f7821r != Shader.TileMode.CLAMP;
    }

    private final void o(boolean z3) {
        W1.a aVar = this.f7815l;
        if (aVar == null) {
            return;
        }
        Uri uriF = aVar.f();
        D1.a aVarC = aVar.c();
        b.c cVarK = k(aVarC);
        ArrayList arrayList = new ArrayList();
        S0.a aVar2 = this.f7824u;
        if (aVar2 != null) {
            arrayList.add(aVar2);
        }
        b bVar = this.f7823t;
        if (bVar != null) {
            arrayList.add(bVar);
        }
        T0.d dVarA = e.f7805b.a(arrayList);
        H0.g resizeOptions = z3 ? getResizeOptions() : null;
        if (aVarC == D1.a.f594c) {
            AbstractC0616d.a().g(uriF);
        }
        T0.c cVarI = T0.c.x(uriF).J(dVarA).N(resizeOptions).y(true).K(this.f7828y).I(cVarK);
        com.facebook.react.views.image.c cVar = this.f7811B;
        com.facebook.react.views.image.c cVar2 = com.facebook.react.views.image.c.f7801e;
        if (cVar == cVar2) {
            cVarI.E(EnumC0189n.f1226d);
        }
        b.a aVar3 = D1.b.f599D;
        j.c(cVarI);
        D1.b bVarB = aVar3.b(cVarI, this.f7829z, aVarC);
        AbstractC0643b abstractC0643b = this.f7812i;
        j.d(abstractC0643b, "null cannot be cast to non-null type com.facebook.drawee.controller.AbstractDraweeControllerBuilder<*, com.facebook.imagepipeline.request.ImageRequest, com.facebook.common.references.CloseableReference<com.facebook.imagepipeline.image.CloseableImage>, com.facebook.imagepipeline.image.ImageInfo>");
        abstractC0643b.x();
        abstractC0643b.B(bVarB).y(true).D(getController());
        Object obj = this.f7813j;
        if (obj != null) {
            j.e(abstractC0643b.z(obj), "setCallerContext(...)");
        }
        W1.a aVar4 = this.f7816m;
        if (aVar4 != null) {
            T0.c cVarK2 = T0.c.x(aVar4.f()).J(dVarA).N(resizeOptions).y(true).K(this.f7828y);
            if (this.f7811B == cVar2) {
                cVarK2.E(EnumC0189n.f1226d);
            }
            j.e(abstractC0643b.C(cVarK2.a()), "setLowResImageRequest(...)");
        }
        g gVar = this.f7825v;
        if (gVar == null || this.f7826w == null) {
            InterfaceC0645d interfaceC0645d = this.f7826w;
            if (interfaceC0645d != null) {
                abstractC0643b.A(interfaceC0645d);
            } else if (gVar != null) {
                abstractC0643b.A(gVar);
            }
        } else {
            p0.f fVar = new p0.f();
            fVar.a(this.f7825v);
            fVar.a(this.f7826w);
            abstractC0643b.A(fVar);
        }
        if (this.f7825v != null) {
            ((C0690a) getHierarchy()).A(this.f7825v);
        }
        setController(abstractC0643b.a());
        abstractC0643b.x();
    }

    private final void p() {
        this.f7815l = null;
        if (this.f7814k.isEmpty()) {
            List list = this.f7814k;
            a.C0045a c0045a = W1.a.f2831f;
            Context context = getContext();
            j.e(context, "getContext(...)");
            list.add(c0045a.a(context));
        } else if (l()) {
            b.a aVarA = W1.b.a(getWidth(), getHeight(), this.f7814k);
            this.f7815l = aVarA.f2838a;
            this.f7816m = aVarA.f2839b;
            return;
        }
        this.f7815l = (W1.a) this.f7814k.get(0);
    }

    private final boolean q(W1.a aVar) {
        int i3 = c.f7832b[this.f7811B.ordinal()];
        if (i3 != 1) {
            if (i3 != 2) {
                return false;
            }
        } else if (!f0.f.k(aVar.f()) && !f0.f.l(aVar.f())) {
            return false;
        }
        return true;
    }

    private final void r(String str) {
        if (!C0527a.f9198b || C0655b.c()) {
            return;
        }
        Context context = getContext();
        j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
        S1.c.d((ReactContext) context, "ReactImageView: Image source \"" + str + "\" doesn't exist");
    }

    public final W1.a getImageSource$ReactAndroid_release() {
        return this.f7815l;
    }

    @Override // android.widget.ImageView, android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    public final void n() {
        if (this.f7822s) {
            if (!l() || (getWidth() > 0 && getHeight() > 0)) {
                p();
                W1.a aVar = this.f7815l;
                if (aVar == null) {
                    return;
                }
                boolean zQ = q(aVar);
                if (!zQ || (getWidth() > 0 && getHeight() > 0)) {
                    if (!m() || (getWidth() > 0 && getHeight() > 0)) {
                        C0690a c0690a = (C0690a) getHierarchy();
                        c0690a.v(this.f7820q);
                        Drawable drawable = this.f7817n;
                        if (drawable != null) {
                            c0690a.y(drawable, this.f7820q);
                        }
                        Drawable drawable2 = this.f7818o;
                        if (drawable2 != null) {
                            c0690a.y(drawable2, q.f10120g);
                        }
                        C0693d c0693dQ = c0690a.q();
                        if (c0693dQ != null) {
                            int i3 = this.f7819p;
                            if (i3 != 0) {
                                c0693dQ.n(i3);
                            } else {
                                c0693dQ.p(C0693d.a.BITMAP_ONLY);
                            }
                            c0690a.B(c0693dQ);
                        }
                        int i4 = this.f7827x;
                        if (i4 < 0) {
                            i4 = aVar.g() ? 0 : 300;
                        }
                        c0690a.x(i4);
                        o(zQ);
                        this.f7822s = false;
                    }
                }
            }
        }
    }

    @Override // android.widget.ImageView, android.view.View
    public void onDraw(Canvas canvas) {
        j.f(canvas, "canvas");
        C0433a.a(this, canvas);
        try {
            super.onDraw(canvas);
        } catch (RuntimeException e3) {
            if (this.f7825v != null) {
                Context context = getContext();
                j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
                EventDispatcher eventDispatcherC = H0.c((ReactContext) context, getId());
                if (eventDispatcherC != null) {
                    eventDispatcherC.g(com.facebook.react.views.image.b.f7790o.a(H0.f(this), getId(), e3));
                }
            }
        }
    }

    @Override // android.view.View
    protected void onSizeChanged(int i3, int i4, int i5, int i6) {
        super.onSizeChanged(i3, i4, i5, i6);
        if (i3 <= 0 || i4 <= 0) {
            return;
        }
        this.f7822s = this.f7822s || l() || m();
        n();
    }

    @Override // android.view.View
    public void setBackgroundColor(int i3) {
        C0433a.n(this, Integer.valueOf(i3));
    }

    public final void setBlurRadius(float f3) {
        int iB = ((int) C0444f0.f7603a.b(f3)) / 2;
        this.f7824u = iB == 0 ? null : new S0.a(2, iB);
        this.f7822s = true;
    }

    public final void setBorderColor(int i3) {
        C0433a.p(this, n.f2478c, Integer.valueOf(i3));
    }

    public final void setBorderRadius(float f3) {
        C0433a.q(this, Q1.d.f2402b, Float.isNaN(f3) ? null : new W(C0444f0.f7603a.d(f3), X.f7535b));
    }

    public final void setBorderWidth(float f3) {
        C0433a.s(this, n.f2478c, Float.valueOf(f3));
    }

    public final void setControllerListener(InterfaceC0645d interfaceC0645d) {
        this.f7826w = interfaceC0645d;
        this.f7822s = true;
        n();
    }

    public final void setDefaultSource(String str) {
        W1.c cVarA = W1.c.f2840b.a();
        Context context = getContext();
        j.e(context, "getContext(...)");
        Drawable drawableE = cVarA.e(context, str);
        if (j.b(this.f7817n, drawableE)) {
            return;
        }
        this.f7817n = drawableE;
        this.f7822s = true;
    }

    public final void setFadeDuration(int i3) {
        this.f7827x = i3;
    }

    public final void setHeaders(ReadableMap readableMap) {
        this.f7829z = readableMap;
    }

    public final void setImageSource$ReactAndroid_release(W1.a aVar) {
        this.f7815l = aVar;
    }

    public final void setLoadingIndicatorSource(String str) {
        W1.c cVarA = W1.c.f2840b.a();
        Context context = getContext();
        j.e(context, "getContext(...)");
        Drawable drawableE = cVarA.e(context, str);
        RunnableC0682b runnableC0682b = drawableE != null ? new RunnableC0682b(drawableE, 1000) : null;
        if (j.b(this.f7818o, runnableC0682b)) {
            return;
        }
        this.f7818o = runnableC0682b;
        this.f7822s = true;
    }

    public final void setOverlayColor(int i3) {
        if (this.f7819p != i3) {
            this.f7819p = i3;
            this.f7822s = true;
        }
    }

    public final void setProgressiveRenderingEnabled(boolean z3) {
        this.f7828y = z3;
    }

    public final void setResizeMethod(com.facebook.react.views.image.c cVar) {
        j.f(cVar, "resizeMethod");
        if (this.f7811B != cVar) {
            this.f7811B = cVar;
            this.f7822s = true;
        }
    }

    public final void setResizeMultiplier(float f3) {
        if (Math.abs(this.f7810A - f3) > 9.999999747378752E-5d) {
            this.f7810A = f3;
            this.f7822s = true;
        }
    }

    public final void setScaleType(q qVar) {
        j.f(qVar, "scaleType");
        if (this.f7820q != qVar) {
            this.f7820q = qVar;
            this.f7822s = true;
        }
    }

    public final void setShouldNotifyLoadEvents(boolean z3) {
        if (z3 == (this.f7825v != null)) {
            return;
        }
        if (z3) {
            Context context = getContext();
            j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
            this.f7825v = new d(H0.c((ReactContext) context, getId()), this);
        } else {
            this.f7825v = null;
        }
        this.f7822s = true;
    }

    public final void setSource(ReadableArray readableArray) {
        ArrayList arrayList = new ArrayList();
        if (readableArray == null || readableArray.size() == 0) {
            a.C0045a c0045a = W1.a.f2831f;
            Context context = getContext();
            j.e(context, "getContext(...)");
            arrayList.add(c0045a.a(context));
        } else {
            if (readableArray.size() == 1) {
                ReadableMap map = readableArray.getMap(0);
                if (map == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                D1.a aVarJ = j(map.getString("cache"));
                Context context2 = getContext();
                j.e(context2, "getContext(...)");
                W1.a aVar = new W1.a(context2, map.getString("uri"), 0.0d, 0.0d, aVarJ, 12, null);
                if (j.b(Uri.EMPTY, aVar.f())) {
                    r(map.getString("uri"));
                    a.C0045a c0045a2 = W1.a.f2831f;
                    Context context3 = getContext();
                    j.e(context3, "getContext(...)");
                    aVar = c0045a2.a(context3);
                }
                arrayList.add(aVar);
            } else {
                int size = readableArray.size();
                for (int i3 = 0; i3 < size; i3++) {
                    ReadableMap map2 = readableArray.getMap(i3);
                    if (map2 != null) {
                        D1.a aVarJ2 = j(map2.getString("cache"));
                        Context context4 = getContext();
                        j.e(context4, "getContext(...)");
                        W1.a aVar2 = new W1.a(context4, map2.getString("uri"), map2.getDouble("width"), map2.getDouble("height"), aVarJ2);
                        if (j.b(Uri.EMPTY, aVar2.f())) {
                            r(map2.getString("uri"));
                            a.C0045a c0045a3 = W1.a.f2831f;
                            Context context5 = getContext();
                            j.e(context5, "getContext(...)");
                            aVar2 = c0045a3.a(context5);
                        }
                        arrayList.add(aVar2);
                    }
                }
            }
        }
        if (j.b(this.f7814k, arrayList)) {
            return;
        }
        this.f7814k.clear();
        this.f7814k.addAll(arrayList);
        this.f7822s = true;
    }

    public final void setTileMode(Shader.TileMode tileMode) {
        j.f(tileMode, "tileMode");
        if (this.f7821r != tileMode) {
            this.f7821r = tileMode;
            this.f7823t = m() ? new b() : null;
            this.f7822s = true;
        }
    }
}
