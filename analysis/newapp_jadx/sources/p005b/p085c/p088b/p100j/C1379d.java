package p005b.p085c.p088b.p100j;

import com.alipay.sdk.app.AlipayResultActivity;
import java.util.concurrent.CountDownLatch;
import p005b.p085c.p088b.p089a.C1349f;

/* renamed from: b.c.b.j.d */
/* loaded from: classes.dex */
public class C1379d implements AlipayResultActivity.InterfaceC3191a {

    /* renamed from: a */
    public final /* synthetic */ CountDownLatch f1291a;

    /* renamed from: b */
    public final /* synthetic */ C1380e f1292b;

    public C1379d(C1380e c1380e, CountDownLatch countDownLatch) {
        this.f1292b = c1380e;
        this.f1291a = countDownLatch;
    }

    @Override // com.alipay.sdk.app.AlipayResultActivity.InterfaceC3191a
    /* renamed from: a */
    public void mo426a(int i2, String str, String str2) {
        this.f1292b.f1299g = C1349f.m356a(i2, str, str2);
        this.f1291a.countDown();
    }
}
