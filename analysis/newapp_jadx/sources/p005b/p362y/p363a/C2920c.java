package p005b.p362y.p363a;

import android.R;
import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewGroup;
import com.shuyu.gsyvideoplayer.R$id;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import p005b.p362y.p363a.AbstractC2919b;

/* renamed from: b.y.a.c */
/* loaded from: classes2.dex */
public class C2920c extends AbstractC2919b {

    /* renamed from: q */
    public static final int f8021q = R$id.small_id;

    /* renamed from: r */
    public static final int f8022r = R$id.full_id;

    /* renamed from: s */
    @SuppressLint({"StaticFieldLeak"})
    public static C2920c f8023s;

    public C2920c() {
        this.f7992b = new AbstractC2919b.i(Looper.getMainLooper());
        this.f7993c = new Handler();
    }

    /* renamed from: b */
    public static boolean m3393b(Context context) {
        if (((ViewGroup) CommonUtil.scanForActivity(context).findViewById(R.id.content)).findViewById(f8022r) == null) {
            return false;
        }
        CommonUtil.hideNavKey(context);
        if (m3394c().lastListener() == null) {
            return true;
        }
        m3394c().lastListener().onBackFullscreen();
        return true;
    }

    /* renamed from: c */
    public static synchronized C2920c m3394c() {
        C2920c c2920c;
        synchronized (C2920c.class) {
            if (f8023s == null) {
                f8023s = new C2920c();
            }
            c2920c = f8023s;
        }
        return c2920c;
    }

    /* renamed from: d */
    public static void m3395d() {
        if (m3394c().listener() != null) {
            m3394c().listener().onVideoPause();
        }
    }

    /* renamed from: e */
    public static void m3396e() {
        if (m3394c().listener() != null) {
            m3394c().listener().onVideoResume();
        }
    }

    /* renamed from: f */
    public static void m3397f() {
        if (m3394c().listener() != null) {
            m3394c().listener().onCompletion();
        }
        m3394c().releaseMediaPlayer();
    }
}
