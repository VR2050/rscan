package p005b.p006a.p007a.p008a.p017r.p018k;

import androidx.core.app.NotificationCompat;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p017r.p019l.C0936a;
import p005b.p006a.p007a.p008a.p017r.p019l.C0938c;
import p005b.p199l.p258c.AbstractC2496z;
import p458k.AbstractC4393m0;
import p505n.InterfaceC5013h;

/* renamed from: b.a.a.a.r.k.d */
/* loaded from: classes2.dex */
public final class C0930d<T> implements InterfaceC5013h<AbstractC4393m0, Object> {

    /* renamed from: a */
    @NotNull
    public final AbstractC2496z<T> f449a;

    /* renamed from: b */
    @NotNull
    public final Type f450b;

    public C0930d(@NotNull AbstractC2496z<T> adapter, @NotNull Type type) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(type, "type");
        this.f449a = adapter;
        this.f450b = type;
    }

    @Override // p505n.InterfaceC5013h
    public Object convert(AbstractC4393m0 abstractC4393m0) {
        byte[] bArr;
        JSONObject jSONObject;
        String str;
        Boolean valueOf;
        AbstractC4393m0 value = abstractC4393m0;
        Intrinsics.checkNotNullParameter(value, "value");
        byte[] m5007b = value.m5007b();
        try {
            jSONObject = new JSONObject(new String(m5007b, Charsets.UTF_8));
        } catch (Exception unused) {
            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(2, secretKeySpec);
                bArr = cipher.doFinal(m5007b);
            } catch (Exception e2) {
                System.out.println(e2.toString());
                bArr = null;
            }
            Intrinsics.checkNotNullExpressionValue(bArr, "AesSecurity().decryptOrigin(buffer, NetConfig.AES_KEY)");
            jSONObject = new JSONObject(new String(bArr, Charsets.UTF_8));
        }
        if (Intrinsics.areEqual(jSONObject.optString(NotificationCompat.CATEGORY_STATUS), "n")) {
            String error = jSONObject.optString("error");
            int optInt = jSONObject.optInt("errorCode");
            if (optInt == 2002) {
                Intrinsics.checkNotNullExpressionValue(error, "error");
                throw new C0938c(error, 2002);
            }
            Intrinsics.checkNotNullExpressionValue(error, "error");
            throw new C0936a(error, Integer.valueOf(optInt));
        }
        try {
            str = jSONObject.getString("data");
            if (str == null) {
                str = jSONObject.toString();
                Intrinsics.checkNotNullExpressionValue(str, "jsonObject.toString()");
            }
        } catch (Exception unused2) {
            str = null;
        }
        if (str == null) {
            valueOf = null;
        } else {
            valueOf = Boolean.valueOf(str.length() > 0);
        }
        if (Intrinsics.areEqual(valueOf, Boolean.TRUE) && !Intrinsics.areEqual(str, "null")) {
            return this.f449a.m2866a(str);
        }
        if (Intrinsics.areEqual(this.f450b, String.class)) {
            return this.f449a.m2866a("");
        }
        Type type = this.f450b;
        if (type instanceof ParameterizedType) {
            Type rawType = ((ParameterizedType) type).getRawType();
            Objects.requireNonNull(rawType, "null cannot be cast to non-null type java.lang.Class<*>");
            Class cls = (Class) rawType;
            if (cls.isAssignableFrom(List.class)) {
                return this.f449a.m2866a("[]");
            }
            if (cls.isAssignableFrom(Map.class)) {
                return this.f449a.m2866a("{}");
            }
        }
        if (Intrinsics.areEqual(this.f450b, Object.class)) {
            return this.f449a.m2866a("{}");
        }
        return null;
    }
}
