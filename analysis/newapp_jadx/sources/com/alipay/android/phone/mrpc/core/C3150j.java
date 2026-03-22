package com.alipay.android.phone.mrpc.core;

import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;

/* renamed from: com.alipay.android.phone.mrpc.core.j */
/* loaded from: classes.dex */
public final class C3150j extends AbstractC3131a {

    /* renamed from: g */
    private InterfaceC3147g f8549g;

    public C3150j(InterfaceC3147g interfaceC3147g, Method method, int i2, String str, byte[] bArr, boolean z) {
        super(method, i2, str, bArr, "application/x-www-form-urlencoded", z);
        this.f8549g = interfaceC3147g;
    }

    @Override // com.alipay.android.phone.mrpc.core.InterfaceC3162v
    /* renamed from: a */
    public final Object mo3675a() {
        C3155o c3155o = new C3155o(this.f8549g.mo3669a());
        c3155o.m3692a(this.f8518b);
        c3155o.m3688a(this.f8521e);
        c3155o.m3691a(this.f8522f);
        c3155o.m3689a("id", String.valueOf(this.f8520d));
        c3155o.m3689a("operationType", this.f8519c);
        c3155o.m3689a("gzip", String.valueOf(this.f8549g.mo3672d()));
        c3155o.m3690a(new BasicHeader("uuid", UUID.randomUUID().toString()));
        List<Header> m3653b = this.f8549g.mo3671c().m3653b();
        if (m3653b != null && !m3653b.isEmpty()) {
            Iterator<Header> it = m3653b.iterator();
            while (it.hasNext()) {
                c3155o.m3690a(it.next());
            }
        }
        StringBuilder sb = new StringBuilder("threadid = ");
        sb.append(Thread.currentThread().getId());
        sb.append("; ");
        sb.append(c3155o.toString());
        try {
            C3161u c3161u = this.f8549g.mo3670b().mo3655a(c3155o).get();
            if (c3161u != null) {
                return c3161u.m3723b();
            }
            throw new RpcException((Integer) 9, "response is null");
        } catch (InterruptedException e2) {
            throw new RpcException(13, "", e2);
        } catch (CancellationException e3) {
            throw new RpcException(13, "", e3);
        } catch (ExecutionException e4) {
            Throwable cause = e4.getCause();
            if (cause == null || !(cause instanceof HttpException)) {
                throw new RpcException(9, "", e4);
            }
            HttpException httpException = (HttpException) cause;
            int code = httpException.getCode();
            switch (code) {
                case 1:
                    code = 2;
                    break;
                case 2:
                    code = 3;
                    break;
                case 3:
                    code = 4;
                    break;
                case 4:
                    code = 5;
                    break;
                case 5:
                    code = 6;
                    break;
                case 6:
                    code = 7;
                    break;
                case 7:
                    code = 8;
                    break;
                case 8:
                    code = 15;
                    break;
                case 9:
                    code = 16;
                    break;
            }
            throw new RpcException(Integer.valueOf(code), httpException.getMsg());
        }
    }
}
