package p005b.p362y.p363a.p374j;

import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;

/* renamed from: b.y.a.j.a */
/* loaded from: classes2.dex */
public class ViewOnTouchListenerC2948a implements View.OnTouchListener {

    /* renamed from: c */
    public int f8076c;

    /* renamed from: e */
    public int f8077e;

    /* renamed from: f */
    public int f8078f;

    /* renamed from: g */
    public int f8079g;

    /* renamed from: h */
    public int f8080h;

    /* renamed from: i */
    public int f8081i;

    /* renamed from: j */
    public GSYBaseVideoPlayer f8082j;

    public ViewOnTouchListenerC2948a(GSYBaseVideoPlayer gSYBaseVideoPlayer, int i2, int i3) {
        this.f8078f = i2;
        this.f8079g = i3;
        this.f8082j = gSYBaseVideoPlayer;
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent motionEvent) {
        int rawX = (int) motionEvent.getRawX();
        int rawY = (int) motionEvent.getRawY();
        int action = motionEvent.getAction() & 255;
        if (action == 0) {
            this.f8076c = rawX;
            this.f8077e = rawY;
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.f8082j.getLayoutParams();
            this.f8080h = rawX - layoutParams.leftMargin;
            this.f8081i = rawY - layoutParams.topMargin;
        } else {
            if (action == 1) {
                return Math.abs(this.f8077e - rawY) >= 5 || Math.abs(this.f8076c - rawX) >= 5;
            }
            if (action == 2) {
                FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.f8082j.getLayoutParams();
                int i2 = rawX - this.f8080h;
                layoutParams2.leftMargin = i2;
                int i3 = rawY - this.f8081i;
                layoutParams2.topMargin = i3;
                int i4 = this.f8078f;
                if (i2 >= i4) {
                    layoutParams2.leftMargin = i4;
                }
                int i5 = this.f8079g;
                if (i3 >= i5) {
                    layoutParams2.topMargin = i5;
                }
                if (layoutParams2.leftMargin <= 0) {
                    layoutParams2.leftMargin = 0;
                }
                if (layoutParams2.topMargin <= 0) {
                    layoutParams2.topMargin = 0;
                }
                this.f8082j.setLayoutParams(layoutParams2);
            }
        }
        return false;
    }
}
