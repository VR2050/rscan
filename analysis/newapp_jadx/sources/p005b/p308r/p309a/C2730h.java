package p005b.p308r.p309a;

import android.content.Context;
import android.graphics.Canvas;
import android.widget.ImageView;
import com.kaopiz.kprogresshud.R$drawable;

/* renamed from: b.r.a.h */
/* loaded from: classes2.dex */
public class C2730h extends ImageView implements InterfaceC2726d {

    /* renamed from: c */
    public float f7430c;

    /* renamed from: e */
    public int f7431e;

    /* renamed from: f */
    public boolean f7432f;

    /* renamed from: g */
    public Runnable f7433g;

    public C2730h(Context context) {
        super(context);
        setImageResource(R$drawable.kprogresshud_spinner);
        this.f7431e = 83;
        this.f7433g = new RunnableC2729g(this);
    }

    @Override // android.widget.ImageView, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f7432f = true;
        post(this.f7433g);
    }

    @Override // android.widget.ImageView, android.view.View
    public void onDetachedFromWindow() {
        this.f7432f = false;
        super.onDetachedFromWindow();
    }

    @Override // android.widget.ImageView, android.view.View
    public void onDraw(Canvas canvas) {
        canvas.rotate(this.f7430c, getWidth() / 2, getHeight() / 2);
        super.onDraw(canvas);
    }

    @Override // p005b.p308r.p309a.InterfaceC2726d
    public void setAnimationSpeed(float f2) {
        this.f7431e = (int) (83.0f / f2);
    }
}
