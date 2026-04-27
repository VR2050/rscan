package io.openinstall.sdk;

import android.content.Context;
import com.fm.openinstall.Configuration;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class g implements cx {
    private final Context a;
    private final Configuration b;

    g(Context context, Configuration configuration) {
        this.a = context;
        this.b = configuration;
    }

    @Override // io.openinstall.sdk.cx
    public List<cw> a() {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new o(this.a));
        arrayList.add(new r(this.a, this.b));
        if (ea.d(this.a) || this.b.isAdEnabled()) {
            arrayList.add(new l());
            s sVar = new s(this.a);
            arrayList.add(new p(this.b, sVar));
            arrayList.add(new n(this.b, sVar));
            arrayList.add(new m(this.a, this.b));
            arrayList.add(new q(this.a, this.b));
        }
        return arrayList;
    }
}
