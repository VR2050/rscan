package p005b.p143g.p144a.p147m.p148s;

import android.content.ContentResolver;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import androidx.annotation.NonNull;
import java.io.FileNotFoundException;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.m.s.a */
/* loaded from: classes.dex */
public final class C1587a extends AbstractC1598l<AssetFileDescriptor> {
    public C1587a(ContentResolver contentResolver, Uri uri) {
        super(contentResolver, uri);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    /* renamed from: a */
    public Class<AssetFileDescriptor> mo832a() {
        return AssetFileDescriptor.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1598l
    /* renamed from: c */
    public void mo833c(AssetFileDescriptor assetFileDescriptor) {
        assetFileDescriptor.close();
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1598l
    /* renamed from: e */
    public AssetFileDescriptor mo834e(Uri uri, ContentResolver contentResolver) {
        AssetFileDescriptor openAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uri, "r");
        if (openAssetFileDescriptor != null) {
            return openAssetFileDescriptor;
        }
        throw new FileNotFoundException(C1499a.m632r("FileDescriptor is null for: ", uri));
    }
}
