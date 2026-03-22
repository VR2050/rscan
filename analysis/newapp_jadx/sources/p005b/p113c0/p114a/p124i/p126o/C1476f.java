package p005b.p113c0.p114a.p124i.p126o;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.Map;
import p005b.p113c0.p114a.p124i.C1462h;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p130l.C1494f;
import p005b.p113c0.p114a.p130l.InterfaceC1497i;

/* renamed from: b.c0.a.i.o.f */
/* loaded from: classes2.dex */
public class C1476f extends C1462h implements InterfaceC1473c {

    /* renamed from: b */
    public InterfaceC1457c f1461b;

    /* renamed from: c */
    public InterfaceC1497i<String, InterfaceC1472b> f1462c;

    /* renamed from: d */
    public InterfaceC1497i<String, String> f1463d;

    /* renamed from: e */
    public Map<String, String> f1464e;

    public C1476f(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1497i<String, InterfaceC1472b> interfaceC1497i, @NonNull InterfaceC1497i<String, String> interfaceC1497i2, @NonNull Map<String, String> map) {
        super(interfaceC1457c);
        this.f1461b = interfaceC1457c;
        this.f1462c = new C1494f(Collections.unmodifiableMap(interfaceC1497i));
        this.f1463d = new C1494f(Collections.unmodifiableMap(interfaceC1497i2));
        this.f1464e = Collections.unmodifiableMap(map);
    }

    @Override // p005b.p113c0.p114a.p124i.p126o.InterfaceC1473c
    @NonNull
    /* renamed from: g */
    public InterfaceC1497i<String, InterfaceC1472b> mo552g() {
        return this.f1462c;
    }

    @Override // p005b.p113c0.p114a.p124i.C1462h, p005b.p113c0.p114a.p124i.InterfaceC1457c
    @Nullable
    /* renamed from: i */
    public String mo527i(@NonNull String str) {
        String str2 = (String) ((C1494f) this.f1463d).m567c(str);
        return TextUtils.isEmpty(str2) ? this.f1461b.mo527i(str) : str2;
    }
}
