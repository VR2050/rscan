package P1;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.Transformation;

/* JADX INFO: loaded from: classes.dex */
class m extends Animation implements j {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final View f2202b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f2203c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private float f2204d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private float f2205e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float f2206f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f2207g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f2208h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f2209i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f2210j;

    public m(View view, int i3, int i4, int i5, int i6) {
        this.f2202b = view;
        c(i3, i4, i5, i6);
    }

    private void c(int i3, int i4, int i5, int i6) {
        this.f2203c = this.f2202b.getX() - this.f2202b.getTranslationX();
        this.f2204d = this.f2202b.getY() - this.f2202b.getTranslationY();
        this.f2207g = this.f2202b.getWidth();
        int height = this.f2202b.getHeight();
        this.f2208h = height;
        this.f2205e = i3 - this.f2203c;
        this.f2206f = i4 - this.f2204d;
        this.f2209i = i5 - this.f2207g;
        this.f2210j = i6 - height;
    }

    @Override // P1.j
    public void a(int i3, int i4, int i5, int i6) {
        c(i3, i4, i5, i6);
    }

    @Override // android.view.animation.Animation
    protected void applyTransformation(float f3, Transformation transformation) {
        float f4 = this.f2203c + (this.f2205e * f3);
        float f5 = this.f2204d + (this.f2206f * f3);
        this.f2202b.layout(Math.round(f4), Math.round(f5), Math.round(f4 + this.f2207g + (this.f2209i * f3)), Math.round(f5 + this.f2208h + (this.f2210j * f3)));
    }

    @Override // android.view.animation.Animation
    public boolean willChangeBounds() {
        return true;
    }
}
