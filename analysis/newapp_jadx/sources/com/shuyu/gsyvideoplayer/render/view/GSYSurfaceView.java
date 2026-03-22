package com.shuyu.gsyvideoplayer.render.view;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.util.AttributeSet;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.utils.MeasureHelper;
import java.io.File;
import p005b.p362y.p363a.p366f.InterfaceC2928d;
import p005b.p362y.p363a.p366f.InterfaceC2929e;
import p005b.p362y.p363a.p369i.p371c.AbstractC2942b;
import p005b.p362y.p363a.p369i.p372d.InterfaceC2944a;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c;

/* loaded from: classes2.dex */
public class GSYSurfaceView extends SurfaceView implements SurfaceHolder.Callback2, InterfaceC2944a, MeasureHelper.MeasureFormVideoParamsListener {

    /* renamed from: c */
    public static final /* synthetic */ int f10763c = 0;

    /* renamed from: e */
    public InterfaceC2947c f10764e;

    /* renamed from: f */
    public MeasureHelper.MeasureFormVideoParamsListener f10765f;

    /* renamed from: g */
    public MeasureHelper f10766g;

    public GSYSurfaceView(Context context) {
        super(context);
        this.f10766g = new MeasureHelper(this, this);
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: a */
    public Bitmap mo3408a() {
        Debuger.printfLog(getClass().getSimpleName() + " not support initCover now");
        return null;
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: b */
    public void mo3409b(InterfaceC2928d interfaceC2928d, boolean z) {
        Debuger.printfLog(getClass().getSimpleName() + " not support taskShotPic now");
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: c */
    public void mo3410c() {
        Debuger.printfLog(getClass().getSimpleName() + " not support onRenderResume now");
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: d */
    public void mo3411d(File file, boolean z, InterfaceC2929e interfaceC2929e) {
        Debuger.printfLog(getClass().getSimpleName() + " not support saveFrame now");
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoHeight() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10765f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getCurrentVideoHeight();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoWidth() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10765f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getCurrentVideoWidth();
        }
        return 0;
    }

    public InterfaceC2947c getIGSYSurfaceListener() {
        return this.f10764e;
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public View getRenderView() {
        return this;
    }

    public int getSizeH() {
        return getHeight();
    }

    public int getSizeW() {
        return getWidth();
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getVideoSarDen() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10765f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getVideoSarDen();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getVideoSarNum() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10765f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getVideoSarNum();
        }
        return 0;
    }

    @Override // android.view.SurfaceView, android.view.View
    public void onMeasure(int i2, int i3) {
        this.f10766g.prepareMeasure(i2, i3, (int) getRotation());
        setMeasuredDimension(this.f10766g.getMeasuredWidth(), this.f10766g.getMeasuredHeight());
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setGLEffectFilter(GSYVideoGLView.InterfaceC4091c interfaceC4091c) {
        Debuger.printfLog(getClass().getSimpleName() + " not support setGLEffectFilter now");
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setGLMVPMatrix(float[] fArr) {
        Debuger.printfLog(getClass().getSimpleName() + " not support setGLMVPMatrix now");
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setGLRenderer(AbstractC2942b abstractC2942b) {
        Debuger.printfLog(getClass().getSimpleName() + " not support setGLRenderer now");
    }

    public void setIGSYSurfaceListener(InterfaceC2947c interfaceC2947c) {
        getHolder().addCallback(this);
        this.f10764e = interfaceC2947c;
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setRenderMode(int i2) {
        Debuger.printfLog(getClass().getSimpleName() + " not support setRenderMode now");
    }

    public void setRenderTransform(Matrix matrix) {
        Debuger.printfLog(getClass().getSimpleName() + " not support setRenderTransform now");
    }

    public void setVideoParamsListener(MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener) {
        this.f10765f = measureFormVideoParamsListener;
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceChanged(SurfaceHolder surfaceHolder, int i2, int i3, int i4) {
        InterfaceC2947c interfaceC2947c = this.f10764e;
        if (interfaceC2947c != null) {
            interfaceC2947c.onSurfaceSizeChanged(surfaceHolder.getSurface(), i3, i4);
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceCreated(SurfaceHolder surfaceHolder) {
        InterfaceC2947c interfaceC2947c = this.f10764e;
        if (interfaceC2947c != null) {
            interfaceC2947c.onSurfaceAvailable(surfaceHolder.getSurface());
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceDestroyed(SurfaceHolder surfaceHolder) {
        InterfaceC2947c interfaceC2947c = this.f10764e;
        if (interfaceC2947c != null) {
            interfaceC2947c.onSurfaceDestroyed(surfaceHolder.getSurface());
        }
    }

    @Override // android.view.SurfaceHolder.Callback2
    public void surfaceRedrawNeeded(SurfaceHolder surfaceHolder) {
    }

    public GSYSurfaceView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f10766g = new MeasureHelper(this, this);
    }
}
