package com.jbzd.media.movecartoons.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;
import android.widget.ImageView;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p308r.p309a.InterfaceC2726d;

@SuppressLint({"AppCompatCustomView"})
/* loaded from: classes2.dex */
public class JuhuaView extends ImageView implements InterfaceC2726d {
    private int mFrameTime;
    private boolean mNeedToUpdateView;
    private float mRotateDegrees;
    private Runnable mUpdateViewRunnable;

    public JuhuaView(Context context) {
        super(context);
        init();
    }

    private void init() {
        setImageResource(R.drawable.progress);
        try {
            setColorFilter(getContext().getResources().getColor(R.color.black));
        } catch (Exception unused) {
        }
        this.mFrameTime = 83;
        this.mUpdateViewRunnable = new Runnable() { // from class: com.jbzd.media.movecartoons.view.JuhuaView.1
            @Override // java.lang.Runnable
            public void run() {
                JuhuaView.this.mRotateDegrees += 30.0f;
                JuhuaView juhuaView = JuhuaView.this;
                juhuaView.mRotateDegrees = juhuaView.mRotateDegrees < 360.0f ? JuhuaView.this.mRotateDegrees : JuhuaView.this.mRotateDegrees - 360.0f;
                JuhuaView.this.invalidate();
                if (JuhuaView.this.mNeedToUpdateView) {
                    JuhuaView.this.postDelayed(this, r0.mFrameTime);
                }
            }
        };
    }

    @Override // android.widget.ImageView, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.mNeedToUpdateView = true;
        post(this.mUpdateViewRunnable);
    }

    @Override // android.widget.ImageView, android.view.View
    public void onDetachedFromWindow() {
        this.mNeedToUpdateView = false;
        super.onDetachedFromWindow();
    }

    @Override // android.widget.ImageView, android.view.View
    public void onDraw(Canvas canvas) {
        canvas.rotate(this.mRotateDegrees, getWidth() / 2, getHeight() / 2);
        super.onDraw(canvas);
    }

    @Override // p005b.p308r.p309a.InterfaceC2726d
    public void setAnimationSpeed(float f2) {
        this.mFrameTime = (int) (83.0f / f2);
    }

    public JuhuaView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        init();
    }
}
