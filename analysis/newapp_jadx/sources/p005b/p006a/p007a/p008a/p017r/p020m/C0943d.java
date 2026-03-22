package p005b.p006a.p007a.p008a.p017r.p020m;

import android.os.Handler;
import android.os.Looper;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import java.io.IOException;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import kotlin.TuplesKt;
import kotlin.collections.MapsKt__MapsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p006a.p007a.p008a.p017r.C0925i;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p258c.C2480j;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p458k.C4375d0;
import p458k.C4379f0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4486w;
import p458k.C4489z;
import p458k.InterfaceC4369a0;
import p458k.p459p0.p463g.C4430g;
import p474l.C4744f;
import p474l.InterfaceC4746h;

/* renamed from: b.a.a.a.r.m.d */
/* loaded from: classes2.dex */
public final class C0943d implements InterfaceC4369a0 {

    /* renamed from: a */
    public static final /* synthetic */ int f469a = 0;

    /* renamed from: b */
    @NotNull
    public final Handler f470b = new Handler(Looper.getMainLooper());

    @Override // p458k.InterfaceC4369a0
    @NotNull
    /* renamed from: a */
    public C4389k0 mo280a(@NotNull InterfaceC4369a0.a chain) {
        byte[] bArr;
        JSONObject jSONObject;
        InterfaceC4746h mo4927k;
        InterfaceC4746h mo4927k2;
        Intrinsics.checkNotNullParameter(chain, "chain");
        C4430g c4430g = (C4430g) chain;
        C4381g0 c4381g0 = c4430g.f11739f;
        C4389k0 m5139d = Intrinsics.areEqual(c4381g0.f11441c, "POST") ? c4430g.m5139d(m286b(c4381g0)) : c4430g.m5139d(c4381g0);
        AbstractC4393m0 abstractC4393m0 = m5139d.f11491k;
        byte[] bArr2 = null;
        C4744f buffer = (abstractC4393m0 == null || (mo4927k2 = abstractC4393m0.mo4927k()) == null) ? null : mo4927k2.getBuffer();
        byte[] mo5386l = buffer == null ? null : buffer.clone().mo5386l();
        if (mo5386l != null) {
            if (!(mo5386l.length == 0)) {
                try {
                    try {
                        jSONObject = new JSONObject(new String(mo5386l, Charsets.UTF_8));
                    } catch (Exception unused) {
                    }
                } catch (Exception unused2) {
                    try {
                        SecretKeySpec secretKeySpec = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
                        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        cipher.init(2, secretKeySpec);
                        bArr = cipher.doFinal(mo5386l);
                    } catch (Exception e2) {
                        System.out.println(e2.toString());
                        bArr = null;
                    }
                    Intrinsics.checkNotNullExpressionValue(bArr, "AesSecurity().decryptOrigin(data, NetConfig.AES_KEY)");
                    jSONObject = new JSONObject(new String(bArr, Charsets.UTF_8));
                }
                if (jSONObject.optInt("errorCode") == 2002) {
                    C4375d0.a aVar = new C4375d0.a();
                    aVar.m4956a(new C0942c());
                    aVar.m4956a(new C0941b());
                    C4375d0 c4375d0 = new C4375d0(aVar);
                    AbstractC4387j0 body = C2354n.m2445X1(MapsKt__MapsKt.hashMapOf(TuplesKt.m5318to("device_id", C0887j.m211a())));
                    C4381g0.a aVar2 = new C4381g0.a();
                    String m270b = C0925i.f437a.m270b();
                    if (!StringsKt__StringsJVMKt.endsWith$default(m270b, "/", false, 2, null)) {
                        m270b = Intrinsics.stringPlus(m270b, "/");
                    }
                    aVar2.m4978h(Intrinsics.stringPlus(m270b, "user/login"));
                    Intrinsics.checkParameterIsNotNull(body, "body");
                    aVar2.m4975e("POST", body);
                    AbstractC4393m0 abstractC4393m02 = ((C4379f0) c4375d0.mo4955a(aVar2.m4972b())).m4965a().f11491k;
                    C4744f buffer2 = (abstractC4393m02 == null || (mo4927k = abstractC4393m02.mo4927k()) == null) ? null : mo4927k.getBuffer();
                    byte[] mo5386l2 = buffer2 == null ? null : buffer2.clone().mo5386l();
                    if (mo5386l2 != null) {
                        if (!(mo5386l2.length == 0)) {
                            try {
                                try {
                                    SecretKeySpec secretKeySpec2 = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
                                    Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
                                    cipher2.init(2, secretKeySpec2);
                                    bArr2 = cipher2.doFinal(mo5386l2);
                                } catch (Exception e3) {
                                    System.out.println(e3.toString());
                                }
                                Intrinsics.checkNotNullExpressionValue(bArr2, "AesSecurity().decryptOrigin(data, NetConfig.AES_KEY)");
                                TokenBean tokenBean = (TokenBean) new C2480j().m2848b(new JSONObject(new String(bArr2, Charsets.UTF_8)).optString("data"), TokenBean.class);
                                MyApp myApp = MyApp.f9891f;
                                MyApp.m4188i(tokenBean);
                                return c4430g.m5139d(m286b(c4381g0));
                            } catch (Exception unused3) {
                                this.f470b.post(new Runnable() { // from class: b.a.a.a.r.m.a
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        int i2 = C0943d.f469a;
                                    }
                                });
                                throw new IOException("can't get Token");
                            }
                        }
                    }
                    this.f470b.post(new Runnable() { // from class: b.a.a.a.r.m.a
                        @Override // java.lang.Runnable
                        public final void run() {
                            int i2 = C0943d.f469a;
                        }
                    });
                    throw new IOException("response is null");
                }
            }
        }
        return m5139d;
    }

    /* renamed from: b */
    public final C4381g0 m286b(C4381g0 c4381g0) {
        AbstractC4387j0 body = c4381g0.f11443e;
        if (body == null || body.mo4920a() == 0) {
            body = C2354n.m2445X1(new HashMap());
        } else if (body instanceof C4486w) {
            HashMap hashMap = new HashMap();
            int i2 = 0;
            C4486w c4486w = (C4486w) body;
            int size = c4486w.f12027c.size();
            if (size > 0) {
                while (true) {
                    int i3 = i2 + 1;
                    C4489z.b bVar = C4489z.f12044b;
                    hashMap.put(C4489z.b.m5304e(bVar, c4486w.f12027c.get(i2), 0, 0, true, 3), C4489z.b.m5304e(bVar, c4486w.f12028d.get(i2), 0, 0, true, 3));
                    if (i3 >= size) {
                        break;
                    }
                    i2 = i3;
                }
            }
            body = C2354n.m2445X1(hashMap);
        }
        C4381g0.a aVar = new C4381g0.a(c4381g0);
        Intrinsics.checkParameterIsNotNull(body, "body");
        aVar.m4975e("POST", body);
        return aVar.m4972b();
    }
}
