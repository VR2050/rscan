package p005b.p085c.p088b.p092c;

import android.content.Context;
import android.os.ConditionVariable;
import android.text.TextUtils;
import com.alipay.apmobilesecuritysdk.face.APSecuritySdk;
import java.util.HashMap;
import java.util.concurrent.Callable;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.c.c */
/* loaded from: classes.dex */
public final class CallableC1358c implements Callable<String> {

    /* renamed from: a */
    public final /* synthetic */ C1373a f1220a;

    /* renamed from: b */
    public final /* synthetic */ Context f1221b;

    /* renamed from: c */
    public final /* synthetic */ HashMap f1222c;

    public CallableC1358c(C1373a c1373a, Context context, HashMap hashMap) {
        this.f1220a = c1373a;
        this.f1221b = context;
        this.f1222c = hashMap;
    }

    @Override // java.util.concurrent.Callable
    public String call() {
        C1373a c1373a = this.f1220a;
        Context context = this.f1221b;
        HashMap hashMap = this.f1222c;
        String[] strArr = {""};
        try {
            APSecuritySdk aPSecuritySdk = APSecuritySdk.getInstance(context);
            ConditionVariable conditionVariable = new ConditionVariable();
            aPSecuritySdk.initToken(0, hashMap, new C1357b(strArr, conditionVariable));
            conditionVariable.block(3000L);
        } catch (Throwable th) {
            C4195m.m4816l(th);
            C1353c.m363d(c1373a, "third", "GetApdidEx", th);
        }
        if (TextUtils.isEmpty(strArr[0])) {
            C1353c.m362c(c1373a, "third", "GetApdidNull", "missing token");
        }
        StringBuilder m586H = C1499a.m586H("ap:");
        m586H.append(strArr[0]);
        C4195m.m4787T("mspl", m586H.toString());
        return strArr[0];
    }
}
