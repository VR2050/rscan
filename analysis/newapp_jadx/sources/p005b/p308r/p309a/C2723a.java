package p005b.p308r.p309a;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import com.kaopiz.kprogresshud.R$color;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.r.a.a */
/* loaded from: classes2.dex */
public class C2723a extends View implements InterfaceC2725c {

    /* renamed from: c */
    public Paint f7397c;

    /* renamed from: e */
    public Paint f7398e;

    /* renamed from: f */
    public RectF f7399f;

    /* renamed from: g */
    public int f7400g;

    public C2723a(Context context) {
        super(context);
        this.f7400g = 100;
        Paint paint = new Paint(1);
        this.f7397c = paint;
        paint.setStyle(Paint.Style.STROKE);
        this.f7397c.setStrokeWidth(C2354n.m2434U(3.0f, getContext()));
        this.f7397c.setColor(-1);
        Paint paint2 = new Paint(1);
        this.f7398e = paint2;
        paint2.setStyle(Paint.Style.STROKE);
        this.f7398e.setStrokeWidth(C2354n.m2434U(3.0f, getContext()));
        this.f7398e.setColor(context.getResources().getColor(R$color.kprogresshud_grey_color));
        this.f7399f = new RectF();
    }

    @Override // p005b.p308r.p309a.InterfaceC2725c
    /* renamed from: a */
    public void mo3239a(int i2) {
        this.f7400g = i2;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float f2 = (0 * 360.0f) / this.f7400g;
        canvas.drawArc(this.f7399f, 270.0f, f2, false, this.f7397c);
        canvas.drawArc(this.f7399f, f2 + 270.0f, 360.0f - f2, false, this.f7398e);
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
        this.f7399f.set(m2434U, m2434U, i2 - r4, i3 - r4);
    }
}
