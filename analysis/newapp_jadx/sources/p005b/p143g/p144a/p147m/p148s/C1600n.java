package p005b.p143g.p144a.p147m.p148s;

import android.content.res.AssetManager;
import androidx.annotation.NonNull;
import java.io.InputStream;

/* renamed from: b.g.a.m.s.n */
/* loaded from: classes.dex */
public class C1600n extends AbstractC1588b<InputStream> {
    public C1600n(AssetManager assetManager, String str) {
        super(assetManager, str);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    /* renamed from: a */
    public Class<InputStream> mo832a() {
        return InputStream.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1588b
    /* renamed from: c */
    public void mo836c(InputStream inputStream) {
        inputStream.close();
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1588b
    /* renamed from: e */
    public InputStream mo838e(AssetManager assetManager, String str) {
        return assetManager.open(str);
    }
}
