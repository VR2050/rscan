package com.jbzd.media.movecartoons.view.viewgroup;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Region;
import android.graphics.drawable.ColorDrawable;
import android.util.AttributeSet;
import androidx.cardview.widget.CardView;
import com.jbzd.media.movecartoons.R$styleable;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class RadiusCardView extends CardView {
    private float blRadiu;
    private float brRadiu;
    private float tlRadiu;
    private float trRadiu;

    public RadiusCardView(Context context) {
        this(context, null);
    }

    private RectF getRectF() {
        Rect rect = new Rect();
        getDrawingRect(rect);
        return new RectF(rect);
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        Path path = new Path();
        RectF rectF = getRectF();
        float f2 = this.tlRadiu;
        float f3 = this.trRadiu;
        float f4 = this.brRadiu;
        float f5 = this.blRadiu;
        path.addRoundRect(rectF, new float[]{f2, f2, f3, f3, f4, f4, f5, f5}, Path.Direction.CW);
        canvas.clipPath(path, Region.Op.INTERSECT);
        super.onDraw(canvas);
    }

    public RadiusCardView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, R.attr.materialCardViewStyle);
    }

    public RadiusCardView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        setRadius(0.0f);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.RadiusCardView);
        float dimension = obtainStyledAttributes.getDimension(2, -1.0f);
        if (dimension >= 0.0f) {
            this.tlRadiu = dimension;
            this.trRadiu = dimension;
            this.brRadiu = dimension;
            this.blRadiu = dimension;
        } else {
            this.tlRadiu = obtainStyledAttributes.getDimension(3, 0.0f);
            this.trRadiu = obtainStyledAttributes.getDimension(4, 0.0f);
            this.brRadiu = obtainStyledAttributes.getDimension(1, 0.0f);
            this.blRadiu = obtainStyledAttributes.getDimension(0, 0.0f);
        }
        setBackground(new ColorDrawable());
    }
}
