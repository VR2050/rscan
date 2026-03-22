package com.alipay.android.phone.mrpc.core.p387a;

import com.alipay.android.phone.mrpc.core.RpcException;
import java.lang.reflect.Type;
import org.json.JSONObject;
import p005b.p085c.p086a.p087a.C1336e;

/* renamed from: com.alipay.android.phone.mrpc.core.a.d */
/* loaded from: classes.dex */
public final class C3135d extends AbstractC3132a {
    public C3135d(Type type, byte[] bArr) {
        super(type, bArr);
    }

    @Override // com.alipay.android.phone.mrpc.core.p387a.InterfaceC3134c
    /* renamed from: a */
    public final Object mo3648a() {
        try {
            String str = new String(this.f8524b);
            StringBuilder sb = new StringBuilder("threadid = ");
            sb.append(Thread.currentThread().getId());
            sb.append("; rpc response:  ");
            sb.append(str);
            JSONObject jSONObject = new JSONObject(str);
            int i2 = jSONObject.getInt("resultStatus");
            if (i2 == 1000) {
                return this.f8523a == String.class ? jSONObject.optString("result") : C1336e.m344b(jSONObject.optString("result"), this.f8523a);
            }
            throw new RpcException(Integer.valueOf(i2), jSONObject.optString("tips"));
        } catch (Exception e2) {
            StringBuilder sb2 = new StringBuilder("response  =");
            sb2.append(new String(this.f8524b));
            sb2.append(":");
            sb2.append(e2);
            throw new RpcException((Integer) 10, sb2.toString() == null ? "" : e2.getMessage());
        }
    }
}
