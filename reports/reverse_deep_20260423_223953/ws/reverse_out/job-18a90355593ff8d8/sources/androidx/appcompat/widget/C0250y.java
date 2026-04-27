package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;
import android.widget.SeekBar;
import d.AbstractC0502a;

/* JADX INFO: renamed from: androidx.appcompat.widget.y, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0250y extends SeekBar {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0251z f4187b;

    public C0250y(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8784E);
    }

    @Override // android.widget.AbsSeekBar, android.widget.ProgressBar, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        this.f4187b.h();
    }

    @Override // android.widget.AbsSeekBar, android.widget.ProgressBar, android.view.View
    public void jumpDrawablesToCurrentState() {
        super.jumpDrawablesToCurrentState();
        this.f4187b.i();
    }

    @Override // android.widget.AbsSeekBar, android.widget.ProgressBar, android.view.View
    protected synchronized void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        this.f4187b.g(canvas);
    }

    public C0250y(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        c0.a(this, getContext());
        C0251z c0251z = new C0251z(this);
        this.f4187b = c0251z;
        c0251z.c(attributeSet, i3);
    }
}
