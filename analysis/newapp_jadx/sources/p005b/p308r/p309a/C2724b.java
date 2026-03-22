package p005b.p308r.p309a;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.r.a.b */
/* loaded from: classes2.dex */
public class C2724b extends View implements InterfaceC2725c {

    /* renamed from: c */
    public Paint f7401c;

    /* renamed from: e */
    public Paint f7402e;

    /* renamed from: f */
    public RectF f7403f;

    /* renamed from: g */
    public RectF f7404g;

    /* renamed from: h */
    public int f7405h;

    /* renamed from: i */
    public float f7406i;

    public C2724b(Context context) {
        super(context);
        this.f7405h = 100;
        Paint paint = new Paint(1);
        this.f7401c = paint;
        paint.setStyle(Paint.Style.STROKE);
        this.f7401c.setStrokeWidth(C2354n.m2434U(2.0f, getContext()));
        this.f7401c.setColor(-1);
        Paint paint2 = new Paint(1);
        this.f7402e = paint2;
        paint2.setStyle(Paint.Style.FILL);
        this.f7402e.setColor(-1);
        this.f7406i = C2354n.m2434U(5.0f, getContext());
        float f2 = this.f7406i;
        this.f7404g = new RectF(f2, f2, ((getWidth() - this.f7406i) * 0) / this.f7405h, getHeight() - this.f7406i);
        this.f7403f = new RectF();
    }

    @Override // p005b.p308r.p309a.InterfaceC2725c
    /* renamed from: a */
    public void mo3239a(int i2) {
        this.f7405h = i2;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        RectF rectF = this.f7403f;
        canvas.drawRoundRect(rectF, rectF.height() / 2.0f, this.f7403f.height() / 2.0f, this.f7401c);
        RectF rectF2 = this.f7404g;
        canvas.drawRoundRect(rectF2, rectF2.height() / 2.0f, this.f7404g.height() / 2.0f, this.f7402e);
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        setMeasuredDimension(C2354n.m2434U(100.0f, getContext()), C2354n.m2434U(20.0f, getContext()));
    }

    @Override // android.view.View
    public void onSizeChanged(int i2, int i3, int i4, int i5) {
        super.onSizeChanged(i2, i3, i4, i5);
        float m2434U = C2354n.m2434U(2.0f, getContext());
        this.f7403f.set(m2434U, m2434U, i2 - r4, i3 - r4);
    }
}
