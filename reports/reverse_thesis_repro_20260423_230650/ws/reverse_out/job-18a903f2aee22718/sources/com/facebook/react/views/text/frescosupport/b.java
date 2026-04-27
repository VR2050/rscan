package com.facebook.react.views.text.frescosupport;

import T0.c;
import Y1.p;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.widget.TextView;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.views.image.d;
import p0.AbstractC0643b;
import q.g;
import t0.C0690a;
import t0.C0691b;
import w0.C0713b;

/* JADX INFO: loaded from: classes.dex */
class b extends p {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Drawable f8082b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final AbstractC0643b f8083c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final C0713b f8084d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Object f8085e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f8086f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f8087g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Uri f8088h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f8089i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private ReadableMap f8090j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private String f8091k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private TextView f8092l;

    public b(Resources resources, int i3, int i4, int i5, Uri uri, ReadableMap readableMap, AbstractC0643b abstractC0643b, Object obj, String str) {
        this.f8084d = new C0713b(C0691b.t(resources).a());
        this.f8083c = abstractC0643b;
        this.f8085e = obj;
        this.f8087g = i5;
        this.f8088h = uri == null ? Uri.EMPTY : uri;
        this.f8090j = readableMap;
        this.f8089i = (int) C0444f0.h(i4);
        this.f8086f = (int) C0444f0.h(i3);
        this.f8091k = str;
    }

    @Override // Y1.p
    public Drawable a() {
        return this.f8082b;
    }

    @Override // Y1.p
    public int b() {
        return this.f8086f;
    }

    @Override // Y1.p
    public void c() {
        this.f8084d.j();
    }

    @Override // Y1.p
    public void d() {
        this.f8084d.k();
    }

    @Override // android.text.style.ReplacementSpan
    public void draw(Canvas canvas, CharSequence charSequence, int i3, int i4, float f3, int i5, int i6, int i7, Paint paint) {
        if (this.f8082b == null) {
            D1.b bVarA = D1.b.A(c.x(this.f8088h), this.f8090j);
            ((C0690a) this.f8084d.f()).v(d.c(this.f8091k));
            this.f8083c.x();
            this.f8083c.D(this.f8084d.e());
            Object obj = this.f8085e;
            if (obj != null) {
                this.f8083c.z(obj);
            }
            this.f8083c.B(bVarA);
            this.f8084d.o(this.f8083c.a());
            this.f8083c.x();
            Drawable drawable = (Drawable) g.f(this.f8084d.g());
            this.f8082b = drawable;
            drawable.setBounds(0, 0, this.f8089i, this.f8086f);
            int i8 = this.f8087g;
            if (i8 != 0) {
                this.f8082b.setColorFilter(i8, PorterDuff.Mode.SRC_IN);
            }
            this.f8082b.setCallback(this.f8092l);
        }
        canvas.save();
        canvas.translate(f3, ((i6 + ((int) paint.descent())) - (((int) (paint.descent() - paint.ascent())) / 2)) - ((this.f8082b.getBounds().bottom - this.f8082b.getBounds().top) / 2));
        this.f8082b.draw(canvas);
        canvas.restore();
    }

    @Override // Y1.p
    public void e() {
        this.f8084d.j();
    }

    @Override // Y1.p
    public void f() {
        this.f8084d.k();
    }

    @Override // android.text.style.ReplacementSpan
    public int getSize(Paint paint, CharSequence charSequence, int i3, int i4, Paint.FontMetricsInt fontMetricsInt) {
        if (fontMetricsInt != null) {
            int i5 = -this.f8086f;
            fontMetricsInt.ascent = i5;
            fontMetricsInt.descent = 0;
            fontMetricsInt.top = i5;
            fontMetricsInt.bottom = 0;
        }
        return this.f8089i;
    }

    @Override // Y1.p
    public void h(TextView textView) {
        this.f8092l = textView;
    }
}
