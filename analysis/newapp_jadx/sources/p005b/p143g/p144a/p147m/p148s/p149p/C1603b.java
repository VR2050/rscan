package p005b.p143g.p144a.p147m.p148s.p149p;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.MediaStore;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;

/* renamed from: b.g.a.m.s.p.b */
/* loaded from: classes.dex */
public class C1603b implements InterfaceC1590d<InputStream> {

    /* renamed from: c */
    public final Uri f2028c;

    /* renamed from: e */
    public final C1605d f2029e;

    /* renamed from: f */
    public InputStream f2030f;

    /* renamed from: b.g.a.m.s.p.b$a */
    public static class a implements InterfaceC1604c {

        /* renamed from: a */
        public static final String[] f2031a = {"_data"};

        /* renamed from: b */
        public final ContentResolver f2032b;

        public a(ContentResolver contentResolver) {
            this.f2032b = contentResolver;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.p149p.InterfaceC1604c
        /* renamed from: a */
        public Cursor mo850a(Uri uri) {
            return this.f2032b.query(MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI, f2031a, "kind = 1 AND image_id = ?", new String[]{uri.getLastPathSegment()}, null);
        }
    }

    /* renamed from: b.g.a.m.s.p.b$b */
    public static class b implements InterfaceC1604c {

        /* renamed from: a */
        public static final String[] f2033a = {"_data"};

        /* renamed from: b */
        public final ContentResolver f2034b;

        public b(ContentResolver contentResolver) {
            this.f2034b = contentResolver;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.p149p.InterfaceC1604c
        /* renamed from: a */
        public Cursor mo850a(Uri uri) {
            return this.f2034b.query(MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI, f2033a, "kind = 1 AND video_id = ?", new String[]{uri.getLastPathSegment()}, null);
        }
    }

    @VisibleForTesting
    public C1603b(Uri uri, C1605d c1605d) {
        this.f2028c = uri;
        this.f2029e = c1605d;
    }

    /* renamed from: c */
    public static C1603b m848c(Context context, Uri uri, InterfaceC1604c interfaceC1604c) {
        return new C1603b(uri, new C1605d(ComponentCallbacks2C1553c.m735d(context).f1814j.m747e(), interfaceC1604c, ComponentCallbacks2C1553c.m735d(context).f1815k, context.getContentResolver()));
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    /* renamed from: a */
    public Class<InputStream> mo832a() {
        return InputStream.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: b */
    public void mo835b() {
        InputStream inputStream = this.f2030f;
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException unused) {
            }
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    public void cancel() {
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: d */
    public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super InputStream> aVar) {
        try {
            InputStream m849e = m849e();
            this.f2030f = m849e;
            aVar.mo840e(m849e);
        } catch (FileNotFoundException e2) {
            Log.isLoggable("MediaStoreThumbFetcher", 3);
            aVar.mo839c(e2);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:56:0x0045, code lost:
    
        r6.close();
     */
    /* JADX WARN: Code restructure failed: missing block: B:5:0x0026, code lost:
    
        if (r6 != null) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x0043, code lost:
    
        if (r6 != null) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x0048, code lost:
    
        r7 = null;
     */
    /* JADX WARN: Not initialized variable reg: 6, insn: 0x0023: MOVE (r5 I:??[OBJECT, ARRAY]) = (r6 I:??[OBJECT, ARRAY]), block:B:70:0x0023 */
    /* JADX WARN: Removed duplicated region for block: B:12:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x00bb  */
    /* JADX WARN: Removed duplicated region for block: B:20:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00ea  */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.InputStream m849e() {
        /*
            Method dump skipped, instructions count: 238
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p148s.p149p.C1603b.m849e():java.io.InputStream");
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    public EnumC1569a getDataSource() {
        return EnumC1569a.LOCAL;
    }
}
