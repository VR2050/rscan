package p005b.p143g.p144a.p147m.p148s;

import android.content.ContentResolver;
import android.content.UriMatcher;
import android.net.Uri;
import androidx.annotation.NonNull;
import java.io.InputStream;

/* renamed from: b.g.a.m.s.o */
/* loaded from: classes.dex */
public class C1601o extends AbstractC1598l<InputStream> {

    /* renamed from: g */
    public static final UriMatcher f2027g;

    static {
        UriMatcher uriMatcher = new UriMatcher(-1);
        f2027g = uriMatcher;
        uriMatcher.addURI("com.android.contacts", "contacts/lookup/*/#", 1);
        uriMatcher.addURI("com.android.contacts", "contacts/lookup/*", 1);
        uriMatcher.addURI("com.android.contacts", "contacts/#/photo", 2);
        uriMatcher.addURI("com.android.contacts", "contacts/#", 3);
        uriMatcher.addURI("com.android.contacts", "contacts/#/display_photo", 4);
        uriMatcher.addURI("com.android.contacts", "phone_lookup/*", 5);
    }

    public C1601o(ContentResolver contentResolver, Uri uri) {
        super(contentResolver, uri);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    /* renamed from: a */
    public Class<InputStream> mo832a() {
        return InputStream.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1598l
    /* renamed from: c */
    public void mo833c(InputStream inputStream) {
        inputStream.close();
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0025 A[RETURN] */
    @Override // p005b.p143g.p144a.p147m.p148s.AbstractC1598l
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.InputStream mo834e(android.net.Uri r4, android.content.ContentResolver r5) {
        /*
            r3 = this;
            android.content.UriMatcher r0 = p005b.p143g.p144a.p147m.p148s.C1601o.f2027g
            int r0 = r0.match(r4)
            r1 = 1
            if (r0 == r1) goto L19
            r2 = 3
            if (r0 == r2) goto L14
            r2 = 5
            if (r0 == r2) goto L19
            java.io.InputStream r5 = r5.openInputStream(r4)
            goto L23
        L14:
            java.io.InputStream r5 = android.provider.ContactsContract.Contacts.openContactPhotoInputStream(r5, r4, r1)
            goto L23
        L19:
            android.net.Uri r0 = android.provider.ContactsContract.Contacts.lookupContact(r5, r4)
            if (r0 == 0) goto L32
            java.io.InputStream r5 = android.provider.ContactsContract.Contacts.openContactPhotoInputStream(r5, r0, r1)
        L23:
            if (r5 == 0) goto L26
            return r5
        L26:
            java.io.FileNotFoundException r5 = new java.io.FileNotFoundException
            java.lang.String r0 = "InputStream is null for "
            java.lang.String r4 = p005b.p131d.p132a.p133a.C1499a.m632r(r0, r4)
            r5.<init>(r4)
            throw r5
        L32:
            java.io.FileNotFoundException r4 = new java.io.FileNotFoundException
            java.lang.String r5 = "Contact cannot be found"
            r4.<init>(r5)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p148s.C1601o.mo834e(android.net.Uri, android.content.ContentResolver):java.lang.Object");
    }
}
