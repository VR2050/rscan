package p005b.p310s.p311a;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import java.util.Collection;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p310s.p311a.p312o.C2748d;

/* renamed from: b.s.a.l */
/* loaded from: classes2.dex */
public final class C2742l extends Thread {

    /* renamed from: c */
    public final Context f7500c;

    /* renamed from: e */
    public final C2748d f7501e;

    /* renamed from: f */
    public final Map<EnumC2523e, Object> f7502f;

    /* renamed from: g */
    public Handler f7503g;

    /* renamed from: h */
    public HandlerC2738h f7504h;

    /* renamed from: i */
    public final CountDownLatch f7505i = new CountDownLatch(1);

    public C2742l(Context context, C2748d c2748d, HandlerC2738h handlerC2738h, Collection<EnumC2497a> collection, Map<EnumC2523e, Object> map, String str, InterfaceC2537s interfaceC2537s) {
        this.f7500c = context;
        this.f7501e = c2748d;
        this.f7504h = handlerC2738h;
        EnumMap enumMap = new EnumMap(EnumC2523e.class);
        this.f7502f = enumMap;
        if (map != null) {
            enumMap.putAll(map);
        }
        if (collection == null || collection.isEmpty()) {
            SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
            collection = EnumSet.noneOf(EnumC2497a.class);
            if (defaultSharedPreferences.getBoolean("preferences_decode_1D_product", true)) {
                collection.addAll(C2740j.f7485a);
            }
            if (defaultSharedPreferences.getBoolean("preferences_decode_1D_industrial", true)) {
                collection.addAll(C2740j.f7486b);
            }
            if (defaultSharedPreferences.getBoolean("preferences_decode_QR", true)) {
                collection.addAll(C2740j.f7488d);
            }
            if (defaultSharedPreferences.getBoolean("preferences_decode_Data_Matrix", true)) {
                collection.addAll(C2740j.f7489e);
            }
            if (defaultSharedPreferences.getBoolean("preferences_decode_Aztec", false)) {
                collection.addAll(C2740j.f7490f);
            }
            if (defaultSharedPreferences.getBoolean("preferences_decode_PDF417", false)) {
                collection.addAll(C2740j.f7491g);
            }
        }
        enumMap.put((EnumMap) EnumC2523e.POSSIBLE_FORMATS, (EnumC2523e) collection);
        if (str != null) {
            enumMap.put((EnumMap) EnumC2523e.CHARACTER_SET, (EnumC2523e) str);
        }
        enumMap.put((EnumMap) EnumC2523e.NEED_RESULT_POINT_CALLBACK, (EnumC2523e) interfaceC2537s);
        String str2 = "Hints: " + enumMap;
    }

    /* renamed from: a */
    public Handler m3253a() {
        try {
            this.f7505i.await();
        } catch (InterruptedException unused) {
        }
        return this.f7503g;
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        Looper.prepare();
        this.f7503g = new HandlerC2741k(this.f7500c, this.f7501e, this.f7504h, this.f7502f);
        this.f7505i.countDown();
        Looper.loop();
    }
}
