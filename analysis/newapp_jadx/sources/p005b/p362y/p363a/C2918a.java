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

/* renamed from: b.y.a.a */
/* loaded from: classes2.dex */
public class C2918a extends AbstractC2919b {

    /* renamed from: q */
    public static final int f7988q = R$id.ad_small_id;

    /* renamed from: r */
    public static final int f7989r = R$id.ad_full_id;

    /* renamed from: s */
    @SuppressLint({"StaticFieldLeak"})
    public static C2918a f7990s;

    public C2918a() {
        this.f7992b = new AbstractC2919b.i(Looper.getMainLooper());
        this.f7993c = new Handler();
    }

    /* renamed from: b */
    public static boolean m3389b(Context context) {
        if (((ViewGroup) CommonUtil.scanForActivity(context).findViewById(R.id.content)).findViewById(f7989r) == null) {
            return false;
        }
        CommonUtil.hideNavKey(context);
        if (m3390c().lastListener() == null) {
            return true;
        }
        m3390c().lastListener().onBackFullscreen();
        return true;
    }

    /* renamed from: c */
    public static synchronized C2918a m3390c() {
        C2918a c2918a;
        synchronized (C2918a.class) {
            if (f7990s == null) {
                f7990s = new C2918a();
            }
            c2918a = f7990s;
        }
        return c2918a;
    }

    /* renamed from: d */
    public static void m3391d() {
        if (m3390c().listener() != null) {
            m3390c().listener().onCompletion();
        }
        m3390c().releaseMediaPlayer();
    }
}
