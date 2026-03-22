package p005b.p199l.p200a.p201a.p246n1.p247h;

import android.content.Context;
import android.graphics.PointF;
import android.opengl.Matrix;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import androidx.annotation.BinderThread;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.p395ui.PlayerView;
import com.google.android.exoplayer2.p395ui.spherical.SphericalGLSurfaceView;
import p005b.p199l.p200a.p201a.p246n1.p247h.C2273d;

/* renamed from: b.l.a.a.n1.h.h */
/* loaded from: classes.dex */
public class ViewOnTouchListenerC2277h extends GestureDetector.SimpleOnGestureListener implements View.OnTouchListener, C2273d.a {

    /* renamed from: f */
    public final a f5759f;

    /* renamed from: g */
    public final float f5760g;

    /* renamed from: h */
    public final GestureDetector f5761h;

    /* renamed from: j */
    @Nullable
    public InterfaceC2276g f5763j;

    /* renamed from: c */
    public final PointF f5757c = new PointF();

    /* renamed from: e */
    public final PointF f5758e = new PointF();

    /* renamed from: i */
    public volatile float f5762i = 3.1415927f;

    /* renamed from: b.l.a.a.n1.h.h$a */
    public interface a {
    }

    public ViewOnTouchListenerC2277h(Context context, a aVar, float f2) {
        this.f5759f = aVar;
        this.f5760g = f2;
        this.f5761h = new GestureDetector(context, this);
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.p247h.C2273d.a
    @BinderThread
    /* renamed from: a */
    public void mo2172a(float[] fArr, float f2) {
        this.f5762i = -f2;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onDown(MotionEvent motionEvent) {
        this.f5757c.set(motionEvent.getX(), motionEvent.getY());
        return true;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onScroll(MotionEvent motionEvent, MotionEvent motionEvent2, float f2, float f3) {
        float x = (motionEvent2.getX() - this.f5757c.x) / this.f5760g;
        float y = motionEvent2.getY();
        PointF pointF = this.f5757c;
        float f4 = (y - pointF.y) / this.f5760g;
        pointF.set(motionEvent2.getX(), motionEvent2.getY());
        double d2 = this.f5762i;
        float cos = (float) Math.cos(d2);
        float sin = (float) Math.sin(d2);
        PointF pointF2 = this.f5758e;
        pointF2.x -= (cos * x) - (sin * f4);
        float f5 = (cos * f4) + (sin * x) + pointF2.y;
        pointF2.y = f5;
        pointF2.y = Math.max(-45.0f, Math.min(45.0f, f5));
        a aVar = this.f5759f;
        PointF pointF3 = this.f5758e;
        SphericalGLSurfaceView.C3324a c3324a = (SphericalGLSurfaceView.C3324a) aVar;
        synchronized (c3324a) {
            c3324a.f9733j = pointF3.y;
            c3324a.m4127b();
            Matrix.setRotateM(c3324a.f9732i, 0, -pointF3.x, 0.0f, 1.0f, 0.0f);
        }
        return true;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onSingleTapUp(MotionEvent motionEvent) {
        InterfaceC2276g interfaceC2276g = this.f5763j;
        if (interfaceC2276g == null) {
            return false;
        }
        PlayerView playerView = PlayerView.this;
        int i2 = PlayerView.f9670c;
        return playerView.m4116j();
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent motionEvent) {
        return this.f5761h.onTouchEvent(motionEvent);
    }
}
