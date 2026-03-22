package p005b.p327w.p328a.p329f;

import android.content.Context;
import android.os.Environment;
import androidx.work.Data;
import java.io.File;
import p005b.p113c0.p114a.p116h.p118h.C1433a;
import p005b.p113c0.p114a.p116h.p118h.C1434b;
import p005b.p113c0.p114a.p116h.p118h.InterfaceC1435c;
import p005b.p113c0.p114a.p116h.p123m.C1452b;
import p005b.p113c0.p114a.p116h.p123m.C1453c;
import p005b.p327w.p328a.C2821a;

/* renamed from: b.w.a.f.a */
/* loaded from: classes2.dex */
public class C2826a implements InterfaceC1435c {
    @Override // p005b.p113c0.p114a.p116h.p118h.InterfaceC1435c
    /* renamed from: a */
    public void mo497a(Context context, InterfaceC1435c.a aVar) {
        C1433a c1433a = (C1433a) aVar;
        c1433a.f1381b.add(new C1453c(Environment.getExternalStorageDirectory().getAbsolutePath(), "/movies"));
        c1433a.f1381b.add(new C1452b(C2821a.f7664a));
        C1434b.b bVar = new C1434b.b(null);
        bVar.f1386a = 20971520L;
        bVar.f1387b = 524288000L;
        bVar.f1388c = Data.MAX_DATA_BYTES;
        bVar.f1389d = new File(context.getCacheDir(), "_server_upload_cache_");
        c1433a.f1380a = new C1434b(bVar, null);
    }
}
