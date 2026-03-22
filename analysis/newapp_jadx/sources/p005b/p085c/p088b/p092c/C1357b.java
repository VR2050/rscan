package p005b.p085c.p088b.p092c;

import android.os.ConditionVariable;
import com.alipay.apmobilesecuritysdk.face.APSecuritySdk;

/* renamed from: b.c.b.c.b */
/* loaded from: classes.dex */
public final class C1357b implements APSecuritySdk.InitResultListener {

    /* renamed from: a */
    public final /* synthetic */ String[] f1218a;

    /* renamed from: b */
    public final /* synthetic */ ConditionVariable f1219b;

    public C1357b(String[] strArr, ConditionVariable conditionVariable) {
        this.f1218a = strArr;
        this.f1219b = conditionVariable;
    }

    @Override // com.alipay.apmobilesecuritysdk.face.APSecuritySdk.InitResultListener
    public void onResult(APSecuritySdk.TokenResult tokenResult) {
        if (tokenResult != null) {
            this.f1218a[0] = tokenResult.apdidToken;
        }
        this.f1219b.open();
    }
}
