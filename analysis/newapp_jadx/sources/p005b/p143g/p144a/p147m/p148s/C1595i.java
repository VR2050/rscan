package p005b.p143g.p144a.p147m.p148s;

import android.content.ContentResolver;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;
import java.io.FileNotFoundException;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.m.s.i */
/* loaded from: classes.dex */
public class C1595i extends AbstractC1598l<ParcelFileDescriptor> {
    public C1595i(ContentResolver contentResolver, Uri uri) {
        super(contentResolver, uri);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    /* renamed from: a */
    public Class<ParcelFileDescriptor> mo832a() {
        return ParcelFileDescriptor.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1598l
    /* renamed from: c */
    public void mo833c(ParcelFileDescriptor parcelFileDescriptor) {
        parcelFileDescriptor.close();
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1598l
    /* renamed from: e */
    public ParcelFileDescriptor mo834e(Uri uri, ContentResolver contentResolver) {
        AssetFileDescriptor openAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uri, "r");
        if (openAssetFileDescriptor != null) {
            return openAssetFileDescriptor.getParcelFileDescriptor();
        }
        throw new FileNotFoundException(C1499a.m632r("FileDescriptor is null for: ", uri));
    }
}
