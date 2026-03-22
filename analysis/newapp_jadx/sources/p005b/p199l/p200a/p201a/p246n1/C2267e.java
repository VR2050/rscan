package p005b.p199l.p200a.p201a.p246n1;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import androidx.annotation.Nullable;
import java.util.Objects;

/* renamed from: b.l.a.a.n1.e */
/* loaded from: classes.dex */
public final class C2267e {

    /* renamed from: A */
    public float f5677A;

    /* renamed from: B */
    public int f5678B;

    /* renamed from: C */
    public int f5679C;

    /* renamed from: D */
    public int f5680D;

    /* renamed from: E */
    public int f5681E;

    /* renamed from: F */
    public StaticLayout f5682F;

    /* renamed from: G */
    public int f5683G;

    /* renamed from: H */
    public int f5684H;

    /* renamed from: I */
    public int f5685I;

    /* renamed from: J */
    public Rect f5686J;

    /* renamed from: a */
    public final float f5687a;

    /* renamed from: b */
    public final float f5688b;

    /* renamed from: c */
    public final float f5689c;

    /* renamed from: d */
    public final float f5690d;

    /* renamed from: e */
    public final float f5691e;

    /* renamed from: f */
    public final TextPaint f5692f;

    /* renamed from: g */
    public final Paint f5693g;

    /* renamed from: h */
    @Nullable
    public CharSequence f5694h;

    /* renamed from: i */
    @Nullable
    public Layout.Alignment f5695i;

    /* renamed from: j */
    @Nullable
    public Bitmap f5696j;

    /* renamed from: k */
    public float f5697k;

    /* renamed from: l */
    public int f5698l;

    /* renamed from: m */
    public int f5699m;

    /* renamed from: n */
    public float f5700n;

    /* renamed from: o */
    public int f5701o;

    /* renamed from: p */
    public float f5702p;

    /* renamed from: q */
    public float f5703q;

    /* renamed from: r */
    public boolean f5704r;

    /* renamed from: s */
    public boolean f5705s;

    /* renamed from: t */
    public int f5706t;

    /* renamed from: u */
    public int f5707u;

    /* renamed from: v */
    public int f5708v;

    /* renamed from: w */
    public int f5709w;

    /* renamed from: x */
    public int f5710x;

    /* renamed from: y */
    public float f5711y;

    /* renamed from: z */
    public float f5712z;

    public C2267e(Context context) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(null, new int[]{R.attr.lineSpacingExtra, R.attr.lineSpacingMultiplier}, 0, 0);
        this.f5691e = obtainStyledAttributes.getDimensionPixelSize(0, 0);
        this.f5690d = obtainStyledAttributes.getFloat(1, 1.0f);
        obtainStyledAttributes.recycle();
        float round = Math.round((context.getResources().getDisplayMetrics().densityDpi * 2.0f) / 160.0f);
        this.f5687a = round;
        this.f5688b = round;
        this.f5689c = round;
        TextPaint textPaint = new TextPaint();
        this.f5692f = textPaint;
        textPaint.setAntiAlias(true);
        textPaint.setSubpixelText(true);
        Paint paint = new Paint();
        this.f5693g = paint;
        paint.setAntiAlias(true);
        paint.setStyle(Paint.Style.FILL);
    }

    /* renamed from: a */
    public final void m2167a(Canvas canvas, boolean z) {
        if (!z) {
            Objects.requireNonNull(this.f5686J);
            Objects.requireNonNull(this.f5696j);
            canvas.drawBitmap(this.f5696j, (Rect) null, this.f5686J, (Paint) null);
            return;
        }
        StaticLayout staticLayout = this.f5682F;
        if (staticLayout == null) {
            return;
        }
        int save = canvas.save();
        canvas.translate(this.f5683G, this.f5684H);
        if (Color.alpha(this.f5708v) > 0) {
            this.f5693g.setColor(this.f5708v);
            canvas.drawRect(-this.f5685I, 0.0f, staticLayout.getWidth() + this.f5685I, staticLayout.getHeight(), this.f5693g);
        }
        int i2 = this.f5710x;
        if (i2 == 1) {
            this.f5692f.setStrokeJoin(Paint.Join.ROUND);
            this.f5692f.setStrokeWidth(this.f5687a);
            this.f5692f.setColor(this.f5709w);
            this.f5692f.setStyle(Paint.Style.FILL_AND_STROKE);
            staticLayout.draw(canvas);
        } else if (i2 == 2) {
            TextPaint textPaint = this.f5692f;
            float f2 = this.f5688b;
            float f3 = this.f5689c;
            textPaint.setShadowLayer(f2, f3, f3, this.f5709w);
        } else if (i2 == 3 || i2 == 4) {
            boolean z2 = i2 == 3;
            int i3 = z2 ? -1 : this.f5709w;
            int i4 = z2 ? this.f5709w : -1;
            float f4 = this.f5688b / 2.0f;
            this.f5692f.setColor(this.f5706t);
            this.f5692f.setStyle(Paint.Style.FILL);
            float f5 = -f4;
            this.f5692f.setShadowLayer(this.f5688b, f5, f5, i3);
            staticLayout.draw(canvas);
            this.f5692f.setShadowLayer(this.f5688b, f4, f4, i4);
        }
        this.f5692f.setColor(this.f5706t);
        this.f5692f.setStyle(Paint.Style.FILL);
        staticLayout.draw(canvas);
        this.f5692f.setShadowLayer(0.0f, 0.0f, 0.0f, 0);
        canvas.restoreToCount(save);
    }
}
