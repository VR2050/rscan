package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.Bitmap;
import android.util.AttributeSet;
import android.view.View;
import android.widget.RatingBar;
import d.AbstractC0502a;

/* JADX INFO: renamed from: androidx.appcompat.widget.w, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0248w extends RatingBar {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0246u f4186b;

    public C0248w(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8783D);
    }

    @Override // android.widget.RatingBar, android.widget.AbsSeekBar, android.widget.ProgressBar, android.view.View
    protected synchronized void onMeasure(int i3, int i4) {
        super.onMeasure(i3, i4);
        Bitmap bitmapB = this.f4186b.b();
        if (bitmapB != null) {
            setMeasuredDimension(View.resolveSizeAndState(bitmapB.getWidth() * getNumStars(), i3, 0), getMeasuredHeight());
        }
    }

    public C0248w(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        c0.a(this, getContext());
        C0246u c0246u = new C0246u(this);
        this.f4186b = c0246u;
        c0246u.c(attributeSet, i3);
    }
}
