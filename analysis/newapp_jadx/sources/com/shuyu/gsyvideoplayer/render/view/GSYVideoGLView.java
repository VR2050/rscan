package com.shuyu.gsyvideoplayer.render.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Bitmap;
import android.opengl.GLSurfaceView;
import android.opengl.Matrix;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.utils.FileUtils;
import com.shuyu.gsyvideoplayer.utils.MeasureHelper;
import java.io.File;
import java.util.Objects;
import p005b.p362y.p363a.p366f.InterfaceC2928d;
import p005b.p362y.p363a.p366f.InterfaceC2929e;
import p005b.p362y.p363a.p369i.C2939a;
import p005b.p362y.p363a.p369i.p370b.C2940a;
import p005b.p362y.p363a.p369i.p371c.AbstractC2942b;
import p005b.p362y.p363a.p369i.p371c.C2943c;
import p005b.p362y.p363a.p369i.p372d.InterfaceC2944a;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2945a;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2946b;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c;

@SuppressLint({"ViewConstructor"})
/* loaded from: classes2.dex */
public class GSYVideoGLView extends GLSurfaceView implements InterfaceC2945a, InterfaceC2944a, MeasureHelper.MeasureFormVideoParamsListener {

    /* renamed from: c */
    public AbstractC2942b f10773c;

    /* renamed from: e */
    public InterfaceC4091c f10774e;

    /* renamed from: f */
    public MeasureHelper.MeasureFormVideoParamsListener f10775f;

    /* renamed from: g */
    public MeasureHelper f10776g;

    /* renamed from: h */
    public InterfaceC2945a f10777h;

    /* renamed from: i */
    public InterfaceC2947c f10778i;

    /* renamed from: j */
    public float[] f10779j;

    /* renamed from: k */
    public int f10780k;

    /* renamed from: com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView$a */
    public class C4089a implements InterfaceC2928d {

        /* renamed from: a */
        public final /* synthetic */ InterfaceC2929e f10781a;

        /* renamed from: b */
        public final /* synthetic */ File f10782b;

        public C4089a(GSYVideoGLView gSYVideoGLView, InterfaceC2929e interfaceC2929e, File file) {
            this.f10781a = interfaceC2929e;
            this.f10782b = file;
        }

        /* renamed from: a */
        public void m4638a(Bitmap bitmap) {
            if (bitmap == null) {
                this.f10781a.result(false, this.f10782b);
            } else {
                FileUtils.saveBitmap(bitmap, this.f10782b);
                this.f10781a.result(true, this.f10782b);
            }
        }
    }

    /* renamed from: com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView$b */
    public static class C4090b implements InterfaceC2946b {

        /* renamed from: a */
        public final /* synthetic */ Context f10783a;

        /* renamed from: b */
        public final /* synthetic */ ViewGroup f10784b;

        /* renamed from: c */
        public final /* synthetic */ int f10785c;

        /* renamed from: d */
        public final /* synthetic */ InterfaceC2947c f10786d;

        /* renamed from: e */
        public final /* synthetic */ MeasureHelper.MeasureFormVideoParamsListener f10787e;

        /* renamed from: f */
        public final /* synthetic */ int f10788f;

        public C4090b(Context context, ViewGroup viewGroup, int i2, InterfaceC2947c interfaceC2947c, MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener, int i3) {
            this.f10783a = context;
            this.f10784b = viewGroup;
            this.f10785c = i2;
            this.f10786d = interfaceC2947c;
            this.f10787e = measureFormVideoParamsListener;
            this.f10788f = i3;
        }
    }

    /* renamed from: com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView$c */
    public interface InterfaceC4091c {
    }

    public GSYVideoGLView(Context context) {
        super(context);
        this.f10774e = new C2940a();
        this.f10780k = 0;
        m4636f(context);
    }

    /* renamed from: e */
    public static GSYVideoGLView m4635e(Context context, ViewGroup viewGroup, int i2, InterfaceC2947c interfaceC2947c, MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener, InterfaceC4091c interfaceC4091c, float[] fArr, AbstractC2942b abstractC2942b, int i3) {
        if (viewGroup.getChildCount() > 0) {
            viewGroup.removeAllViews();
        }
        GSYVideoGLView gSYVideoGLView = new GSYVideoGLView(context);
        if (abstractC2942b != null) {
            gSYVideoGLView.setCustomRenderer(abstractC2942b);
        }
        gSYVideoGLView.setEffect(interfaceC4091c);
        gSYVideoGLView.setVideoParamsListener(measureFormVideoParamsListener);
        gSYVideoGLView.setRenderMode(i3);
        gSYVideoGLView.setIGSYSurfaceListener(interfaceC2947c);
        gSYVideoGLView.setRotation(i2);
        gSYVideoGLView.setRenderer(gSYVideoGLView.f10773c);
        gSYVideoGLView.setGSYVideoGLRenderErrorListener(new C4090b(context, viewGroup, i2, interfaceC2947c, measureFormVideoParamsListener, i3));
        if (fArr != null && fArr.length == 16) {
            gSYVideoGLView.setMVPMatrix(fArr);
        }
        C2939a.m3404a(viewGroup, gSYVideoGLView);
        return gSYVideoGLView;
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
        if (interfaceC2928d != null) {
            C2943c c2943c = (C2943c) this.f10773c;
            c2943c.f8075z = interfaceC2928d;
            c2943c.f8049c = z;
            c2943c.f8072w = true;
        }
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: c */
    public void mo3410c() {
        requestLayout();
        onResume();
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    /* renamed from: d */
    public void mo3411d(File file, boolean z, InterfaceC2929e interfaceC2929e) {
        C4089a c4089a = new C4089a(this, interfaceC2929e, file);
        C2943c c2943c = (C2943c) this.f10773c;
        c2943c.f8075z = c4089a;
        c2943c.f8049c = z;
        c2943c.f8072w = true;
    }

    /* renamed from: f */
    public final void m4636f(Context context) {
        setEGLContextClientVersion(2);
        this.f10773c = new C2943c();
        this.f10776g = new MeasureHelper(this, this);
        this.f10773c.f8051f = this;
    }

    /* renamed from: g */
    public void m4637g() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10775f;
        if (measureFormVideoParamsListener == null || this.f10780k != 1) {
            return;
        }
        try {
            measureFormVideoParamsListener.getCurrentVideoWidth();
            this.f10775f.getCurrentVideoHeight();
            AbstractC2942b abstractC2942b = this.f10773c;
            if (abstractC2942b != null) {
                abstractC2942b.f8054i = this.f10776g.getMeasuredWidth();
                this.f10773c.f8055j = this.f10776g.getMeasuredHeight();
                Objects.requireNonNull(this.f10773c);
                Objects.requireNonNull(this.f10773c);
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoHeight() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10775f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getCurrentVideoHeight();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoWidth() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10775f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getCurrentVideoWidth();
        }
        return 0;
    }

    public InterfaceC4091c getEffect() {
        return this.f10774e;
    }

    public InterfaceC2947c getIGSYSurfaceListener() {
        return this.f10778i;
    }

    public float[] getMVPMatrix() {
        return this.f10779j;
    }

    public int getMode() {
        return this.f10780k;
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public View getRenderView() {
        return this;
    }

    public AbstractC2942b getRenderer() {
        return this.f10773c;
    }

    public int getSizeH() {
        return getHeight();
    }

    public int getSizeW() {
        return getWidth();
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getVideoSarDen() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10775f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getVideoSarDen();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getVideoSarNum() {
        MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener = this.f10775f;
        if (measureFormVideoParamsListener != null) {
            return measureFormVideoParamsListener.getVideoSarNum();
        }
        return 0;
    }

    @Override // android.view.SurfaceView, android.view.View
    public void onMeasure(int i2, int i3) {
        if (this.f10780k != 1) {
            this.f10776g.prepareMeasure(i2, i3, (int) getRotation());
            setMeasuredDimension(this.f10776g.getMeasuredWidth(), this.f10776g.getMeasuredHeight());
        } else {
            super.onMeasure(i2, i3);
            this.f10776g.prepareMeasure(i2, i3, (int) getRotation());
            m4637g();
        }
    }

    @Override // android.opengl.GLSurfaceView
    public void onResume() {
        int i2;
        super.onResume();
        AbstractC2942b abstractC2942b = this.f10773c;
        if (abstractC2942b == null || (i2 = abstractC2942b.f8054i) == 0 || abstractC2942b.f8055j == 0) {
            return;
        }
        Matrix.scaleM(abstractC2942b.f8052g, 0, i2 / abstractC2942b.f8051f.getWidth(), abstractC2942b.f8055j / abstractC2942b.f8051f.getHeight(), 1.0f);
    }

    public void setCustomRenderer(AbstractC2942b abstractC2942b) {
        this.f10773c = abstractC2942b;
        abstractC2942b.f8051f = this;
        m4637g();
    }

    public void setEffect(InterfaceC4091c interfaceC4091c) {
        if (interfaceC4091c != null) {
            this.f10774e = interfaceC4091c;
            C2943c c2943c = (C2943c) this.f10773c;
            if (interfaceC4091c != null) {
                c2943c.f8063A = interfaceC4091c;
            }
            c2943c.f8056k = true;
            c2943c.f8057l = true;
        }
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setGLEffectFilter(InterfaceC4091c interfaceC4091c) {
        setEffect(interfaceC4091c);
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setGLMVPMatrix(float[] fArr) {
        setMVPMatrix(fArr);
    }

    @Override // p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setGLRenderer(AbstractC2942b abstractC2942b) {
        setCustomRenderer(abstractC2942b);
    }

    public void setGSYVideoGLRenderErrorListener(InterfaceC2946b interfaceC2946b) {
        this.f10773c.f8058m = interfaceC2946b;
    }

    public void setIGSYSurfaceListener(InterfaceC2947c interfaceC2947c) {
        setOnGSYSurfaceListener(this);
        this.f10778i = interfaceC2947c;
    }

    public void setMVPMatrix(float[] fArr) {
        if (fArr != null) {
            this.f10779j = fArr;
            this.f10773c.f8052g = fArr;
        }
    }

    public void setMode(int i2) {
        this.f10780k = i2;
    }

    public void setOnGSYSurfaceListener(InterfaceC2945a interfaceC2945a) {
        this.f10777h = interfaceC2945a;
        this.f10773c.f8050e = interfaceC2945a;
    }

    @Override // android.opengl.GLSurfaceView, p005b.p362y.p363a.p369i.p372d.InterfaceC2944a
    public void setRenderMode(int i2) {
        setMode(i2);
    }

    public void setRenderTransform(android.graphics.Matrix matrix) {
        Debuger.printfLog(getClass().getSimpleName() + " not support setRenderTransform now");
    }

    public void setVideoParamsListener(MeasureHelper.MeasureFormVideoParamsListener measureFormVideoParamsListener) {
        this.f10775f = measureFormVideoParamsListener;
    }

    public GSYVideoGLView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f10774e = new C2940a();
        this.f10780k = 0;
        m4636f(context);
    }
}
