package p005b.p143g.p144a.p147m.p148s;

import android.content.res.AssetManager;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;

/* renamed from: b.g.a.m.s.h */
/* loaded from: classes.dex */
public class C1594h extends AbstractC1588b<ParcelFileDescriptor> {
    public C1594h(AssetManager assetManager, String str) {
        super(assetManager, str);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    /* renamed from: a */
    public Class<ParcelFileDescriptor> mo832a() {
        return ParcelFileDescriptor.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1588b
    /* renamed from: c */
    public void mo836c(ParcelFileDescriptor parcelFileDescriptor) {
        parcelFileDescriptor.close();
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1588b
    /* renamed from: e */
    public ParcelFileDescriptor mo838e(AssetManager assetManager, String str) {
        return assetManager.openFd(str).getParcelFileDescriptor();
    }
}
