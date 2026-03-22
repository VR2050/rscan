package com.alipay.android.phone.mrpc.core.p387a;

import com.alipay.android.phone.mrpc.core.RpcException;
import java.util.ArrayList;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import p005b.p085c.p086a.p087a.C1337f;

/* renamed from: com.alipay.android.phone.mrpc.core.a.e */
/* loaded from: classes.dex */
public final class C3136e extends AbstractC3133b {

    /* renamed from: c */
    private int f8527c;

    /* renamed from: d */
    private Object f8528d;

    public C3136e(int i2, String str, Object obj) {
        super(str, obj);
        this.f8527c = i2;
    }

    @Override // com.alipay.android.phone.mrpc.core.p387a.InterfaceC3137f
    /* renamed from: a */
    public final void mo3649a(Object obj) {
        this.f8528d = obj;
    }

    @Override // com.alipay.android.phone.mrpc.core.p387a.InterfaceC3137f
    /* renamed from: a */
    public final byte[] mo3650a() {
        try {
            ArrayList arrayList = new ArrayList();
            if (this.f8528d != null) {
                arrayList.add(new BasicNameValuePair("extParam", C1337f.m345a(this.f8528d)));
            }
            arrayList.add(new BasicNameValuePair("operationType", this.f8525a));
            StringBuilder sb = new StringBuilder();
            sb.append(this.f8527c);
            arrayList.add(new BasicNameValuePair("id", sb.toString()));
            new StringBuilder("mParams is:").append(this.f8526b);
            Object obj = this.f8526b;
            arrayList.add(new BasicNameValuePair("requestData", obj == null ? "[]" : C1337f.m345a(obj)));
            return URLEncodedUtils.format(arrayList, "utf-8").getBytes();
        } catch (Exception e2) {
            StringBuilder sb2 = new StringBuilder("request  =");
            sb2.append(this.f8526b);
            sb2.append(":");
            sb2.append(e2);
            throw new RpcException(9, sb2.toString() == null ? "" : e2.getMessage(), e2);
        }
    }
}
