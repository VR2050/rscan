package com.shuyu.gsyvideoplayer.render.view;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.graphics.SurfaceTexture;
import android.util.AttributeSet;
import android.view.Surface;
import android.view.TextureView;
import android.view.View;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.utils.FileUtils;
import com.shuyu.gsyvideoplayer.utils.GSYVideoType;
import com.shuyu.gsyvideoplayer.utils.MeasureHelper;
import java.io.File;
import p005b.p362y.p363a.p366f.InterfaceC2928d;
import p005b.p362y.p363a.p366f.InterfaceC2929e;
import p005b.p362y.p363a.p369i.p371c.AbstractC2942b;
import p005b.p362y.p363a.p369i.p372d.InterfaceC2944a;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c;

/* loaded from: classes2.dex */
public class GSYTextureView extends TextureView implements TextureView.SurfaceTextureListener, InterfaceC2944a, MeasureHelper.MeasureFormVideoParamsListener {

    /* renamed from: c */
    public static final /* synthetic */ int f10767c = 0;

    /* renamed from: e */
    public InterfaceC2947c f10768e;

    /* renamed from: f */
    public MeasureHelper.MeasureFormVideoParamsListener f10769f;

    /* renamed from: g */
    public MeasureHelper f10770g;

    /* renamed from: h */
    public SurfaceTexture f10771h;

    /* renamed from: i */
    public Surface f10772i;

    public GSYTextureView(Context context) {
        super(context);
        this.f10770g = new MeasureHelper(this, this);
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: a */
    public Bitmap mo3408a() {
        return getBitmap(Bitmap.createBitmap(getSizeW(), getSizeH(), Bitmap.Config.RGB_565));
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: b */
    public void mo3409b(InterfaceC2928d interfaceC2928d, boolean z) {
        if (z) {
            ((GSYVideoGLView.C4089a) interfaceC2928d).m4638a(getBitmap(Bitmap.createBitmap(getSizeW(), getSizeH(), Bitmap.Config.ARGB_8888)));
        } else {
            ((GSYVideoGLView.C4089a) interfaceC2928d).m4638a(mo3408a());
        }
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: c */
    public void mo3410c() {
        Debuger.printfLog(getClass().getSimpleName() + " not support onRenderResume now");
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: d */
    public void mo3411d(File file, boolean z, InterfaceC2929e interfaceC2929e) {
        if (z) {
            Bitmap bitmap = getBitmap(Bitmap.createBitmap(getSizeW(), getSizeH(), Bitmap.Config.ARGB_8888));
            if (bitmap == null) {
                interfaceC2929e.result(false, file);
                return;
            } else {
                FileUtils.saveBitmap(bitmap, file);
                interfaceC2929e.result(true, file);
                return;
            }
        }
        Bitmap mo3408a = mo3408a();
        if (mo3408a == null) {
            interfaceC2929e.result(false, file);
        } else {
            FileUtils.saveBitmap(mo3408a, file);
            interfaceC2929e.result(true, file);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoHeight() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10769f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getCurrentVideoHeight();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoWidth() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10769f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getCurrentVideoWidth();
        }
        return 0;
    }

    public InterfaceC2947c getIGSYSurfaceListener() {
        return this.f10768e;
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
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10769f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getVideoSarDen();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getVideoSarNum() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10769f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getVideoSarNum();
        }
        return 0;
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        this.f10770g.prepareMeasure(i2, i3, (int) getRotation());
        setMeasuredDimension(this.f10770g.getMeasuredWidth(), this.f10770g.getMeasuredHeight());
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureAvailable(SurfaceTexture surfaceTexture, int i2, int i3) {
        if (!GSYVideoType.isMediaCodecTexture()) {
            Surface surface = new Surface(surfaceTexture);
            this.f10772i = surface;
            InterfaceC2947c interfaceC2947c = this.f10768e;
            if (interfaceC2947c != null) {
                interfaceC2947c.onSurfaceAvailable(surface);
                return;
            }
            return;
        }
        SurfaceTexture surfaceTexture2 = this.f10771h;
        if (surfaceTexture2 == null) {
            this.f10771h = surfaceTexture;
            this.f10772i = new Surface(surfaceTexture);
        } else {
            setSurfaceTexture(surfaceTexture2);
        }
        InterfaceC2947c interfaceC2947c2 = this.f10768e;
        if (interfaceC2947c2 != null) {
            interfaceC2947c2.onSurfaceAvailable(this.f10772i);
        }
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public boolean onSurfaceTextureDestroyed(SurfaceTexture surfaceTexture) {
        InterfaceC2947c interfaceC2947c = this.f10768e;
        if (interfaceC2947c != null) {
            interfaceC2947c.onSurfaceDestroyed(this.f10772i);
        }
        return !GSYVideoType.isMediaCodecTexture() || this.f10771h == null;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureSizeChanged(SurfaceTexture surfaceTexture, int i2, int i3) {
        InterfaceC2947c interfaceC2947c = this.f10768e;
        if (interfaceC2947c != null) {
            interfaceC2947c.onSurfaceSizeChanged(this.f10772i, i2, i3);
        }
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        InterfaceC2947c interfaceC2947c = this.f10768e;
        if (interfaceC2947c != null) {
            interfaceC2947c.onSurfaceUpdated(this.f10772i);
        }
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
        setSurfaceTextureListener(this);
        this.f10768e = interfaceC2947c;
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setRenderMode(int i2) {
        Debuger.printfLog(getClass().getSimpleName() + " not support setRenderMode now");
    }

    public void setRenderTransform(Matrix matrix) {
        setTransform(matrix);
    }

    public void setVideoParamsListener(MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener) {
        this.f10769f = measureFormVideoParamsListener;
    }

    public GSYTextureView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f10770g = new MeasureHelper(this, this);
    }
}
