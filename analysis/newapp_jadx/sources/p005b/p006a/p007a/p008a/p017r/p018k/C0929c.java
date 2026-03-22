package p005b.p006a.p007a.p008a.p017r.p018k;

import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import java.lang.reflect.Type;
import java.util.LinkedHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p458k.AbstractC4387j0;
import p458k.C4371b0;
import p458k.C4385i0;
import p458k.p459p0.C4401c;
import p505n.InterfaceC5013h;

/* renamed from: b.a.a.a.r.k.c */
/* loaded from: classes2.dex */
public final class C0929c<T> implements InterfaceC5013h<T, AbstractC4387j0> {

    /* renamed from: a */
    @NotNull
    public static final C4371b0 f447a;

    /* renamed from: b */
    @NotNull
    public C2480j f448b;

    static {
        C4371b0.a aVar = C4371b0.f11309c;
        f447a = C4371b0.a.m4945a("multipart/form-data");
    }

    public C0929c(@NotNull C2480j gson, @NotNull AbstractC2496z<T> adapter) {
        Intrinsics.checkNotNullParameter(gson, "gson");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        this.f448b = gson;
    }

    @Override // p505n.InterfaceC5013h
    public AbstractC4387j0 convert(Object value) {
        Intrinsics.checkNotNullParameter(value, "value");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("data", value);
        linkedHashMap.put("deviceId", C0887j.m211a());
        StringBuilder sb = new StringBuilder();
        MyApp myApp = MyApp.f9891f;
        TokenBean m4186g = MyApp.m4186g();
        byte[] toRequestBody = null;
        sb.append((Object) (m4186g == null ? null : m4186g.token));
        sb.append('_');
        TokenBean m4186g2 = MyApp.m4186g();
        sb.append((Object) (m4186g2 == null ? null : m4186g2.user_id));
        linkedHashMap.put("token", sb.toString());
        Type type = new C0928b().getType();
        Intrinsics.checkNotNullExpressionValue(type, "object : TypeToken<HashMap<String, Any>>() {}.type");
        String params = this.f448b.m2854h(linkedHashMap, type);
        Intrinsics.checkNotNullExpressionValue(params, "params");
        C2354n.m2454a1(params);
        byte[] bytes = params.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, secretKeySpec);
            toRequestBody = cipher.doFinal(bytes);
        } catch (Exception e2) {
            System.out.println(e2.toString());
        }
        Intrinsics.checkNotNullExpressionValue(toRequestBody, "AesSecurity().encryptOrigin(params.toByteArray(), NetConfig.AES_KEY)");
        C4371b0 c4371b0 = f447a;
        int length = toRequestBody.length;
        Intrinsics.checkParameterIsNotNull(toRequestBody, "$this$toRequestBody");
        C4401c.m5018c(toRequestBody.length, 0, length);
        return new C4385i0(toRequestBody, c4371b0, length, 0);
    }
}
