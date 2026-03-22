package moe.codeest.enviews;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.CornerPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.View;
import android.view.animation.AnticipateInterpolator;
import com.shuyu.gsyvideoplayer.R$styleable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public class ENPlayView extends View {

    /* renamed from: c */
    public int f12776c;

    /* renamed from: e */
    public Paint f12777e;

    /* renamed from: f */
    public Paint f12778f;

    /* renamed from: g */
    public int f12779g;

    /* renamed from: h */
    public int f12780h;

    /* renamed from: i */
    public int f12781i;

    /* renamed from: j */
    public int f12782j;

    /* renamed from: k */
    public int f12783k;

    /* renamed from: l */
    public RectF f12784l;

    /* renamed from: m */
    public RectF f12785m;

    /* renamed from: n */
    public float f12786n;

    /* renamed from: o */
    public Path f12787o;

    /* renamed from: p */
    public Path f12788p;

    /* renamed from: q */
    public PathMeasure f12789q;

    /* renamed from: r */
    public float f12790r;

    /* renamed from: s */
    public int f12791s;

    /* renamed from: moe.codeest.enviews.ENPlayView$a */
    public class C4976a implements ValueAnimator.AnimatorUpdateListener {
        public C4976a() {
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            ENPlayView.this.f12786n = valueAnimator.getAnimatedFraction();
            ENPlayView.this.invalidate();
        }
    }

    public ENPlayView(Context context) {
        super(context);
        this.f12776c = 1;
        this.f12786n = 1.0f;
    }

    /* renamed from: a */
    public final int m5646a(int i2) {
        return (int) TypedValue.applyDimension(1, i2, getContext().getResources().getDisplayMetrics());
    }

    /* renamed from: b */
    public void m5647b() {
        if (this.f12776c == 1) {
            return;
        }
        this.f12776c = 1;
        ValueAnimator ofFloat = ValueAnimator.ofFloat(1.0f, 100.0f);
        ofFloat.setDuration(this.f12791s);
        ofFloat.setInterpolator(new AnticipateInterpolator());
        ofFloat.addUpdateListener(new C4976a());
        if (ofFloat.isRunning()) {
            return;
        }
        ofFloat.start();
    }

    public int getCurrentState() {
        return this.f12776c;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        canvas.drawCircle(this.f12781i, this.f12782j, this.f12779g / 2, this.f12778f);
        float f2 = this.f12786n;
        if (f2 < 0.0f) {
            int i2 = this.f12781i;
            int i3 = this.f12783k;
            int i4 = this.f12782j;
            canvas.drawLine(i2 + i3, (i4 - (i3 * 1.6f)) + (i3 * 10 * f2), i2 + i3, (i3 * 1.6f) + i4 + (i3 * 10 * f2), this.f12777e);
            int i5 = this.f12781i;
            int i6 = this.f12783k;
            int i7 = this.f12782j;
            canvas.drawLine(i5 - i6, i7 - (i6 * 1.6f), i5 - i6, (i6 * 1.6f) + i7, this.f12777e);
            canvas.drawArc(this.f12785m, -105.0f, 360.0f, false, this.f12777e);
            return;
        }
        if (f2 <= 0.3d) {
            int i8 = this.f12781i;
            int i9 = this.f12783k;
            int i10 = this.f12782j;
            canvas.drawLine(i8 + i9, (i10 - (i9 * 1.6f)) + (((i9 * 3.2f) / 0.3f) * f2), i8 + i9, (i9 * 1.6f) + i10, this.f12777e);
            int i11 = this.f12781i;
            int i12 = this.f12783k;
            int i13 = this.f12782j;
            canvas.drawLine(i11 - i12, i13 - (i12 * 1.6f), i11 - i12, (i12 * 1.6f) + i13, this.f12777e);
            float f3 = this.f12786n;
            if (f3 != 0.0f) {
                canvas.drawArc(this.f12784l, 0.0f, f3 * 600.0f, false, this.f12777e);
            }
            canvas.drawArc(this.f12785m, (r1 * 360.0f) - 105.0f, (1.0f - this.f12786n) * 360.0f, false, this.f12777e);
            return;
        }
        if (f2 <= 0.6d) {
            canvas.drawArc(this.f12784l, (f2 - 0.3f) * 600.0f, 180.0f - ((f2 - 0.3f) * 600.0f), false, this.f12777e);
            this.f12788p.reset();
            PathMeasure pathMeasure = this.f12789q;
            float f4 = this.f12790r;
            pathMeasure.getSegment(0.02f * f4, C1499a.m627m(this.f12786n, 0.3f, (f4 * 0.42f) / 0.3f, 0.38f * f4), this.f12788p, true);
            canvas.drawPath(this.f12788p, this.f12777e);
            canvas.drawArc(this.f12785m, (r1 * 360.0f) - 105.0f, (1.0f - this.f12786n) * 360.0f, false, this.f12777e);
            return;
        }
        if (f2 > 0.8d) {
            this.f12788p.reset();
            this.f12789q.getSegment((this.f12786n - 1.0f) * this.f12783k * 10, this.f12790r, this.f12788p, true);
            canvas.drawPath(this.f12788p, this.f12777e);
            return;
        }
        this.f12788p.reset();
        PathMeasure pathMeasure2 = this.f12789q;
        float f5 = this.f12790r;
        float f6 = this.f12786n;
        pathMeasure2.getSegment(C1499a.m627m(f6, 0.6f, (f5 * 0.2f) / 0.2f, 0.02f * f5), C1499a.m627m(f6, 0.6f, (f5 * 0.2f) / 0.2f, 0.8f * f5), this.f12788p, true);
        canvas.drawPath(this.f12788p, this.f12777e);
        canvas.drawArc(this.f12785m, (r1 * 360.0f) - 105.0f, (1.0f - this.f12786n) * 360.0f, false, this.f12777e);
    }

    @Override // android.view.View
    public void onSizeChanged(int i2, int i3, int i4, int i5) {
        super.onSizeChanged(i2, i3, i4, i5);
        int i6 = (i2 * 9) / 10;
        this.f12779g = i6;
        this.f12780h = (i3 * 9) / 10;
        this.f12783k = i6 / m5646a(4);
        this.f12781i = i2 / 2;
        this.f12782j = i3 / 2;
        int i7 = this.f12781i;
        int i8 = this.f12783k;
        int i9 = this.f12782j;
        this.f12784l = new RectF(i7 - i8, (i8 * 0.6f) + i9, i7 + i8, (i8 * 2.6f) + i9);
        int i10 = this.f12781i;
        int i11 = this.f12779g;
        int i12 = this.f12782j;
        int i13 = this.f12780h;
        this.f12785m = new RectF(i10 - (i11 / 2), i12 - (i13 / 2), (i11 / 2) + i10, (i13 / 2) + i12);
        Path path = this.f12787o;
        int i14 = this.f12781i;
        path.moveTo(i14 - r7, (this.f12783k * 1.8f) + this.f12782j);
        Path path2 = this.f12787o;
        int i15 = this.f12781i;
        path2.lineTo(i15 - r7, this.f12782j - (this.f12783k * 1.8f));
        this.f12787o.lineTo(this.f12781i + this.f12783k, this.f12782j);
        this.f12787o.close();
        this.f12789q.setPath(this.f12787o, false);
        this.f12790r = this.f12789q.getLength();
    }

    public void setDuration(int i2) {
        this.f12791s = i2;
    }

    public ENPlayView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f12776c = 1;
        this.f12786n = 1.0f;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.play);
        int color = obtainStyledAttributes.getColor(R$styleable.play_play_line_color, -1);
        int color2 = obtainStyledAttributes.getColor(R$styleable.play_play_bg_line_color, -328966);
        int integer = obtainStyledAttributes.getInteger(R$styleable.play_play_line_width, m5646a(4));
        int integer2 = obtainStyledAttributes.getInteger(R$styleable.play_play_bg_line_width, m5646a(4));
        obtainStyledAttributes.recycle();
        setLayerType(1, null);
        Paint paint = new Paint(1);
        this.f12777e = paint;
        paint.setStyle(Paint.Style.STROKE);
        this.f12777e.setStrokeCap(Paint.Cap.ROUND);
        this.f12777e.setColor(color);
        this.f12777e.setStrokeWidth(integer);
        this.f12777e.setPathEffect(new CornerPathEffect(1.0f));
        Paint paint2 = new Paint(1);
        this.f12778f = paint2;
        paint2.setStyle(Paint.Style.STROKE);
        this.f12778f.setStrokeCap(Paint.Cap.ROUND);
        this.f12778f.setColor(color2);
        this.f12778f.setStrokeWidth(integer2);
        this.f12787o = new Path();
        this.f12788p = new Path();
        this.f12789q = new PathMeasure();
        this.f12791s = 1200;
    }
}
