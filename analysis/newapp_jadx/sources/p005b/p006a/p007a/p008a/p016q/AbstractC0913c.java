package p005b.p006a.p007a.p008a.p016q;

import android.content.Context;
import p476m.p496b.p500b.p501f.AbstractC4932b;
import p476m.p496b.p500b.p501f.InterfaceC4931a;

/* renamed from: b.a.a.a.q.c */
/* loaded from: classes2.dex */
public abstract class AbstractC0913c extends AbstractC4932b {
    public AbstractC0913c(Context context, String str) {
        super(context, str, 1);
    }

    @Override // p476m.p496b.p500b.p501f.AbstractC4932b
    /* renamed from: b */
    public void mo217b(InterfaceC4931a interfaceC4931a) {
        interfaceC4931a.execSQL("CREATE TABLE \"UPLOAD_BEAN\" (\"_id\" INTEGER PRIMARY KEY AUTOINCREMENT ,\"TITLE\" TEXT,\"IMG\" TEXT,\"PREVIEW\" TEXT,\"PREVIEW_M3U8_URL\" TEXT,\"M3U8_URL\" TEXT,\"DURATION\" TEXT,\"QUALITY\" TEXT,\"IMG_SHOW\" TEXT,\"POINT\" TEXT,\"TAG_ID\" TEXT,\"TAG_NAMES\" TEXT,\"LINK\" TEXT,\"CANVAS\" TEXT,\"VIDEO_PATH\" TEXT,\"IMAGE_PATH\" TEXT,\"TIME\" INTEGER NOT NULL ,\"IS_DRAFT\" INTEGER NOT NULL ,\"STATUS\" TEXT,\"TOTAL_SLICES\" INTEGER NOT NULL ,\"PROGRESS_SLICE\" INTEGER NOT NULL );");
    }
}
