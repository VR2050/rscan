package androidx.swiperefreshlayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.OvalShape;
import android.view.animation.Animation;
import android.widget.ImageView;
import androidx.core.view.V;

/* JADX INFO: loaded from: classes.dex */
class a extends ImageView {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Animation.AnimationListener f5281b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f5282c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f5283d;

    /* JADX INFO: renamed from: androidx.swiperefreshlayout.widget.a$a, reason: collision with other inner class name */
    private static class C0082a extends OvalShape {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private Paint f5284b = new Paint();

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f5285c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private a f5286d;

        C0082a(a aVar, int i3) {
            this.f5286d = aVar;
            this.f5285c = i3;
            a((int) rect().width());
        }

        private void a(int i3) {
            float f3 = i3 / 2;
            this.f5284b.setShader(new RadialGradient(f3, f3, this.f5285c, new int[]{1023410176, 0}, (float[]) null, Shader.TileMode.CLAMP));
        }

        @Override // android.graphics.drawable.shapes.OvalShape, android.graphics.drawable.shapes.RectShape, android.graphics.drawable.shapes.Shape
        public void draw(Canvas canvas, Paint paint) {
            float width = this.f5286d.getWidth() / 2;
            float height = this.f5286d.getHeight() / 2;
            canvas.drawCircle(width, height, width, this.f5284b);
            canvas.drawCircle(width, height, r0 - this.f5285c, paint);
        }

        @Override // android.graphics.drawable.shapes.RectShape, android.graphics.drawable.shapes.Shape
        protected void onResize(float f3, float f4) {
            super.onResize(f3, f4);
            a((int) f3);
        }
    }

    a(Context context) {
        ShapeDrawable shapeDrawable;
        super(context);
        float f3 = getContext().getResources().getDisplayMetrics().density;
        int i3 = (int) (1.75f * f3);
        int i4 = (int) (0.0f * f3);
        this.f5282c = (int) (3.5f * f3);
        TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(H.a.f983f);
        this.f5283d = typedArrayObtainStyledAttributes.getColor(H.a.f984g, -328966);
        typedArrayObtainStyledAttributes.recycle();
        if (a()) {
            shapeDrawable = new ShapeDrawable(new OvalShape());
            V.e0(this, f3 * 4.0f);
        } else {
            ShapeDrawable shapeDrawable2 = new ShapeDrawable(new C0082a(this, this.f5282c));
            setLayerType(1, shapeDrawable2.getPaint());
            shapeDrawable2.getPaint().setShadowLayer(this.f5282c, i4, i3, 503316480);
            int i5 = this.f5282c;
            setPadding(i5, i5, i5, i5);
            shapeDrawable = shapeDrawable2;
        }
        shapeDrawable.getPaint().setColor(this.f5283d);
        V.b0(this, shapeDrawable);
    }

    private boolean a() {
        return true;
    }

    public void b(Animation.AnimationListener animationListener) {
        this.f5281b = animationListener;
    }

    @Override // android.view.View
    public void onAnimationEnd() {
        super.onAnimationEnd();
        Animation.AnimationListener animationListener = this.f5281b;
        if (animationListener != null) {
            animationListener.onAnimationEnd(getAnimation());
        }
    }

    @Override // android.view.View
    public void onAnimationStart() {
        super.onAnimationStart();
        Animation.AnimationListener animationListener = this.f5281b;
        if (animationListener != null) {
            animationListener.onAnimationStart(getAnimation());
        }
    }

    @Override // android.widget.ImageView, android.view.View
    protected void onMeasure(int i3, int i4) {
        super.onMeasure(i3, i4);
        if (a()) {
            return;
        }
        setMeasuredDimension(getMeasuredWidth() + (this.f5282c * 2), getMeasuredHeight() + (this.f5282c * 2));
    }

    @Override // android.view.View
    public void setBackgroundColor(int i3) {
        if (getBackground() instanceof ShapeDrawable) {
            ((ShapeDrawable) getBackground()).getPaint().setColor(i3);
            this.f5283d = i3;
        }
    }
}
