package p005b.p310s.p311a;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Point;
import android.media.MediaPlayer;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Vibrator;
import com.king.zxing.CaptureActivity;
import com.king.zxing.R$id;
import com.king.zxing.ViewfinderView;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p310s.p311a.p312o.C2745a;
import p005b.p310s.p311a.p312o.C2746b;
import p005b.p310s.p311a.p312o.C2748d;
import p005b.p310s.p311a.p312o.p313f.C2751b;

/* renamed from: b.s.a.h */
/* loaded from: classes2.dex */
public class HandlerC2738h extends Handler implements InterfaceC2537s {

    /* renamed from: c */
    public final C2731a f7450c;

    /* renamed from: e */
    public final C2742l f7451e;

    /* renamed from: f */
    public int f7452f;

    /* renamed from: g */
    public final C2748d f7453g;

    /* renamed from: h */
    public final ViewfinderView f7454h;

    /* renamed from: i */
    public boolean f7455i;

    /* renamed from: j */
    public boolean f7456j;

    /* renamed from: k */
    public boolean f7457k;

    /* renamed from: l */
    public boolean f7458l;

    public HandlerC2738h(Activity activity, ViewfinderView viewfinderView, C2731a c2731a, Collection<EnumC2497a> collection, Map<EnumC2523e, Object> map, String str, C2748d c2748d) {
        this.f7454h = viewfinderView;
        this.f7450c = c2731a;
        C2742l c2742l = new C2742l(activity, c2748d, this, collection, null, null, this);
        this.f7451e = c2742l;
        c2742l.start();
        this.f7452f = 2;
        this.f7453g = c2748d;
        C2751b c2751b = c2748d.f7531c;
        if (c2751b != null && !c2748d.f7536h) {
            c2751b.f7555b.startPreview();
            c2748d.f7536h = true;
            c2748d.f7532d = new C2745a(c2748d.f7529a, c2751b.f7555b);
        }
        m3244b();
    }

    @Override // p005b.p199l.p266d.InterfaceC2537s
    /* renamed from: a */
    public void mo2935a(C2536r c2536r) {
        float min;
        float f2;
        int max;
        if (this.f7454h != null) {
            C2746b c2746b = this.f7453g.f7530b;
            Point point = c2746b.f7524d;
            Point point2 = c2746b.f7525e;
            int i2 = point.x;
            int i3 = point.y;
            if (i2 < i3) {
                min = (c2536r.f6871a * ((i2 * 1.0f) / point2.y)) - (Math.max(i2, r6) / 2);
                f2 = c2536r.f6872b * ((i3 * 1.0f) / point2.x);
                max = Math.min(point.y, point2.x) / 2;
            } else {
                float f3 = (i3 * 1.0f) / point2.y;
                min = (c2536r.f6871a * ((i2 * 1.0f) / point2.x)) - (Math.min(i3, r4) / 2);
                f2 = c2536r.f6872b * f3;
                max = Math.max(point.x, point2.x) / 2;
            }
            C2536r c2536r2 = new C2536r(min, f2 - max);
            ViewfinderView viewfinderView = this.f7454h;
            if (viewfinderView.f10181r) {
                List<C2536r> list = viewfinderView.f10165H;
                synchronized (list) {
                    list.add(c2536r2);
                    int size = list.size();
                    if (size > 20) {
                        list.subList(0, size - 10).clear();
                    }
                }
            }
        }
    }

    /* renamed from: b */
    public void m3244b() {
        if (this.f7452f == 2) {
            this.f7452f = 1;
            this.f7453g.m3268e(this.f7451e.m3253a(), R$id.decode);
            this.f7454h.invalidate();
        }
    }

    @Override // android.os.Handler
    public void handleMessage(Message message) {
        HandlerC2738h handlerC2738h;
        MediaPlayer mediaPlayer;
        int i2 = message.what;
        if (i2 == R$id.restart_preview) {
            m3244b();
            return;
        }
        if (i2 != R$id.decode_succeeded) {
            if (i2 == R$id.decode_failed) {
                this.f7452f = 1;
                this.f7453g.m3268e(this.f7451e.m3253a(), R$id.decode);
                return;
            }
            return;
        }
        this.f7452f = 2;
        Bundle data = message.getData();
        if (data != null) {
            byte[] byteArray = data.getByteArray("barcode_bitmap");
            if (byteArray != null) {
                BitmapFactory.decodeByteArray(byteArray, 0, byteArray.length, null).copy(Bitmap.Config.ARGB_8888, true);
            }
            data.getFloat("barcode_scaled_factor");
        }
        C2731a c2731a = this.f7450c;
        C2534p c2534p = (C2534p) message.obj;
        final SurfaceHolderCallbackC2739i surfaceHolderCallbackC2739i = c2731a.f7434a;
        surfaceHolderCallbackC2739i.f7467i.m3255b();
        C2737g c2737g = surfaceHolderCallbackC2739i.f7468j;
        synchronized (c2737g) {
            if (c2737g.f7448g && (mediaPlayer = c2737g.f7447f) != null) {
                mediaPlayer.start();
            }
            if (c2737g.f7449h) {
                ((Vibrator) c2737g.f7446e.getApplicationContext().getSystemService("vibrator")).vibrate(200L);
            }
        }
        final String str = c2534p.f6854a;
        if (surfaceHolderCallbackC2739i.f7479u) {
            InterfaceC2744n interfaceC2744n = surfaceHolderCallbackC2739i.f7461B;
            if (interfaceC2744n != null) {
                interfaceC2744n.onResultCallback(str);
            }
            if (!surfaceHolderCallbackC2739i.f7480v || (handlerC2738h = surfaceHolderCallbackC2739i.f7464f) == null) {
                return;
            }
            handlerC2738h.m3244b();
            return;
        }
        if (surfaceHolderCallbackC2739i.f7481w) {
            surfaceHolderCallbackC2739i.f7464f.postDelayed(new Runnable() { // from class: b.s.a.d
                @Override // java.lang.Runnable
                public final void run() {
                    SurfaceHolderCallbackC2739i surfaceHolderCallbackC2739i2 = SurfaceHolderCallbackC2739i.this;
                    String str2 = str;
                    InterfaceC2744n interfaceC2744n2 = surfaceHolderCallbackC2739i2.f7461B;
                    if (interfaceC2744n2 == null || !interfaceC2744n2.onResultCallback(str2)) {
                        Intent intent = new Intent();
                        intent.putExtra(CaptureActivity.KEY_RESULT, str2);
                        surfaceHolderCallbackC2739i2.f7463e.setResult(-1, intent);
                        surfaceHolderCallbackC2739i2.f7463e.finish();
                    }
                }
            }, 100L);
            return;
        }
        InterfaceC2744n interfaceC2744n2 = surfaceHolderCallbackC2739i.f7461B;
        if (interfaceC2744n2 == null || !interfaceC2744n2.onResultCallback(str)) {
            Intent intent = new Intent();
            intent.putExtra(CaptureActivity.KEY_RESULT, str);
            surfaceHolderCallbackC2739i.f7463e.setResult(-1, intent);
            surfaceHolderCallbackC2739i.f7463e.finish();
        }
    }
}
