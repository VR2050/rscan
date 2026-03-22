package p005b.p308r.p309a;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.r.a.f */
/* loaded from: classes2.dex */
public class C2728f extends View implements InterfaceC2725c {

    /* renamed from: c */
    public Paint f7425c;

    /* renamed from: e */
    public Paint f7426e;

    /* renamed from: f */
    public RectF f7427f;

    /* renamed from: g */
    public int f7428g;

    public C2728f(Context context) {
        super(context);
        this.f7428g = 100;
        Paint paint = new Paint(1);
        this.f7425c = paint;
        paint.setStyle(Paint.Style.FILL_AND_STROKE);
        this.f7425c.setStrokeWidth(C2354n.m2434U(0.1f, getContext()));
        this.f7425c.setColor(-1);
        Paint paint2 = new Paint(1);
        this.f7426e = paint2;
        paint2.setStyle(Paint.Style.STROKE);
        this.f7426e.setStrokeWidth(C2354n.m2434U(2.0f, getContext()));
        this.f7426e.setColor(-1);
        this.f7427f = new RectF();
    }

    @Override // p005b.p308r.p309a.InterfaceC2725c
    /* renamed from: a */
    public void mo3239a(int i2) {
        this.f7428g = i2;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        canvas.drawArc(this.f7427f, 270.0f, (0 * 360.0f) / this.f7428g, true, this.f7425c);
        canvas.drawCircle(getWidth() / 2, getHeight() / 2, (getWidth() / 2) - C2354n.m2434U(4.0f, getContext()), this.f7426e);
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        int m2434U = C2354n.m2434U(40.0f, getContext());
        setMeasuredDimension(m2434U, m2434U);
    }

    @Override // android.view.View
    public void onSizeChanged(int i2, int i3, int i4, int i5) {
        super.onSizeChanged(i2, i3, i4, i5);
        float m2434U = C2354n.m2434U(4.0f, getContext());
        this.f7427f.set(m2434U, m2434U, i2 - r4, i3 - r4);
    }
}
