package com.shuyu.gsyvideoplayer.video.base;

import android.content.Context;
import android.graphics.Bitmap;
import android.util.AttributeSet;
import android.view.Surface;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.AttrRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.shuyu.gsyvideoplayer.render.view.GSYSurfaceView;
import com.shuyu.gsyvideoplayer.render.view.GSYTextureView;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import com.shuyu.gsyvideoplayer.utils.GSYVideoType;
import com.shuyu.gsyvideoplayer.utils.MeasureHelper;
import java.util.Objects;
import p005b.p362y.p363a.p369i.C2939a;
import p005b.p362y.p363a.p369i.p370b.C2940a;
import p005b.p362y.p363a.p369i.p371c.AbstractC2942b;
import p005b.p362y.p363a.p369i.p372d.InterfaceC2944a;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c;

/* loaded from: classes2.dex */
public abstract class GSYTextureRenderView extends FrameLayout implements InterfaceC2947c, MeasureHelper.MeasureFormVideoParamsListener {
    public GSYVideoGLView.InterfaceC4091c mEffectFilter;
    public Bitmap mFullPauseBitmap;
    public float[] mMatrixGL;
    public int mMode;
    public AbstractC2942b mRenderer;
    public int mRotate;
    public Surface mSurface;
    public C2939a mTextureView;
    public ViewGroup mTextureViewContainer;

    public GSYTextureRenderView(@NonNull Context context) {
        super(context);
        this.mEffectFilter = new C2940a();
        this.mMatrixGL = null;
        this.mMode = 0;
    }

    public void addTextureView() {
        C2939a c2939a = new C2939a();
        this.mTextureView = c2939a;
        Context context = getContext();
        ViewGroup viewGroup = this.mTextureViewContainer;
        int i2 = this.mRotate;
        GSYVideoGLView.InterfaceC4091c interfaceC4091c = this.mEffectFilter;
        float[] fArr = this.mMatrixGL;
        AbstractC2942b abstractC2942b = this.mRenderer;
        int i3 = this.mMode;
        Objects.requireNonNull(c2939a);
        if (GSYVideoType.getRenderType() == 1) {
            int i4 = GSYSurfaceView.f10763c;
            if (viewGroup.getChildCount() > 0) {
                viewGroup.removeAllViews();
            }
            GSYSurfaceView gSYSurfaceView = new GSYSurfaceView(context);
            gSYSurfaceView.setIGSYSurfaceListener(this);
            gSYSurfaceView.setVideoParamsListener(this);
            gSYSurfaceView.setRotation(i2);
            C2939a.m3404a(viewGroup, gSYSurfaceView);
            c2939a.f8046a = gSYSurfaceView;
            return;
        }
        if (GSYVideoType.getRenderType() == 2) {
            c2939a.f8046a = GSYVideoGLView.m4635e(context, viewGroup, i2, this, this, interfaceC4091c, fArr, abstractC2942b, i3);
            return;
        }
        int i5 = GSYTextureView.f10767c;
        if (viewGroup.getChildCount() > 0) {
            viewGroup.removeAllViews();
        }
        GSYTextureView gSYTextureView = new GSYTextureView(context);
        gSYTextureView.setIGSYSurfaceListener(this);
        gSYTextureView.setVideoParamsListener(this);
        gSYTextureView.setRotation(i2);
        C2939a.m3404a(viewGroup, gSYTextureView);
        c2939a.f8046a = gSYTextureView;
    }

    public void changeTextureViewShowType() {
        if (this.mTextureView != null) {
            int textureParams = getTextureParams();
            ViewGroup.LayoutParams layoutParams = this.mTextureView.f8046a.getRenderView().getLayoutParams();
            layoutParams.width = textureParams;
            layoutParams.height = textureParams;
            InterfaceC2944a interfaceC2944a = this.mTextureView.f8046a;
            if (interfaceC2944a != null) {
                interfaceC2944a.getRenderView().setLayoutParams(layoutParams);
            }
        }
    }

    public GSYVideoGLView.InterfaceC4091c getEffectFilter() {
        return this.mEffectFilter;
    }

    public C2939a getRenderProxy() {
        return this.mTextureView;
    }

    public int getTextureParams() {
        return GSYVideoType.getShowType() != 0 ? -2 : -1;
    }

    public void initCover() {
        C2939a c2939a = this.mTextureView;
        if (c2939a != null) {
            InterfaceC2944a interfaceC2944a = c2939a.f8046a;
            this.mFullPauseBitmap = interfaceC2944a != null ? interfaceC2944a.mo3408a() : null;
        }
    }

    public void onSurfaceAvailable(Surface surface) {
        boolean z;
        C2939a c2939a = this.mTextureView;
        if (c2939a != null) {
            InterfaceC2944a interfaceC2944a = c2939a.f8046a;
            if ((interfaceC2944a != null ? interfaceC2944a.getRenderView() : null) instanceof TextureView) {
                z = true;
                pauseLogic(surface, z);
            }
        }
        z = false;
        pauseLogic(surface, z);
    }

    @Override // p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c
    public boolean onSurfaceDestroyed(Surface surface) {
        setDisplay(null);
        releaseSurface(surface);
        return true;
    }

    @Override // p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c
    public void onSurfaceSizeChanged(Surface surface, int i2, int i3) {
    }

    public void onSurfaceUpdated(Surface surface) {
        releasePauseCover();
    }

    public void pauseLogic(Surface surface, boolean z) {
        this.mSurface = surface;
        if (z) {
            showPauseCover();
        }
        setDisplay(this.mSurface);
    }

    public abstract void releasePauseCover();

    public abstract void releaseSurface(Surface surface);

    public void setCustomGLRenderer(AbstractC2942b abstractC2942b) {
        InterfaceC2944a interfaceC2944a;
        this.mRenderer = abstractC2942b;
        C2939a c2939a = this.mTextureView;
        if (c2939a == null || (interfaceC2944a = c2939a.f8046a) == null) {
            return;
        }
        interfaceC2944a.setGLRenderer(abstractC2942b);
    }

    public abstract void setDisplay(Surface surface);

    public void setEffectFilter(GSYVideoGLView.InterfaceC4091c interfaceC4091c) {
        InterfaceC2944a interfaceC2944a;
        this.mEffectFilter = interfaceC4091c;
        C2939a c2939a = this.mTextureView;
        if (c2939a == null || (interfaceC2944a = c2939a.f8046a) == null) {
            return;
        }
        interfaceC2944a.setGLEffectFilter(interfaceC4091c);
    }

    public void setGLRenderMode(int i2) {
        InterfaceC2944a interfaceC2944a;
        this.mMode = i2;
        C2939a c2939a = this.mTextureView;
        if (c2939a == null || (interfaceC2944a = c2939a.f8046a) == null) {
            return;
        }
        interfaceC2944a.setRenderMode(i2);
    }

    public void setMatrixGL(float[] fArr) {
        InterfaceC2944a interfaceC2944a;
        this.mMatrixGL = fArr;
        C2939a c2939a = this.mTextureView;
        if (c2939a == null || (interfaceC2944a = c2939a.f8046a) == null) {
            return;
        }
        interfaceC2944a.setGLMVPMatrix(fArr);
    }

    public abstract void setSmallVideoTextureView();

    public void setSmallVideoTextureView(View.OnTouchListener onTouchListener) {
        this.mTextureViewContainer.setOnTouchListener(onTouchListener);
        this.mTextureViewContainer.setOnClickListener(null);
        setSmallVideoTextureView();
    }

    public abstract void showPauseCover();

    public GSYTextureRenderView(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mEffectFilter = new C2940a();
        this.mMatrixGL = null;
        this.mMode = 0;
    }

    public GSYTextureRenderView(@NonNull Context context, @Nullable AttributeSet attributeSet, @AttrRes int i2) {
        super(context, attributeSet, i2);
        this.mEffectFilter = new C2940a();
        this.mMatrixGL = null;
        this.mMode = 0;
    }
}
