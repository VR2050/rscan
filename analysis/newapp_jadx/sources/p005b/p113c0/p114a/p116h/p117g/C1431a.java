package p005b.p113c0.p114a.p116h.p117g;

import android.text.TextUtils;
import android.webkit.MimeTypeMap;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import p005b.p113c0.p114a.p124i.InterfaceC1463i;
import p005b.p113c0.p114a.p130l.C1492d;
import p005b.p113c0.p114a.p130l.C1495g;

/* renamed from: b.c0.a.h.g.a */
/* loaded from: classes2.dex */
public class C1431a implements InterfaceC1463i {

    /* renamed from: a */
    public File f1377a;

    public C1431a(File file) {
        if (file == null) {
            throw new IllegalArgumentException("The file cannot be null.");
        }
        this.f1377a = file;
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1463i
    /* renamed from: a */
    public void mo494a(@NonNull OutputStream outputStream) {
        FileInputStream fileInputStream = new FileInputStream(this.f1377a);
        C1492d.m563b(fileInputStream, outputStream);
        try {
            fileInputStream.close();
        } catch (Exception unused) {
        }
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1463i
    /* renamed from: b */
    public long mo495b() {
        return this.f1377a.length();
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1463i
    @Nullable
    /* renamed from: c */
    public C1495g mo496c() {
        String name = this.f1377a.getName();
        C1495g c1495g = C1495g.f1507h;
        String fileExtensionFromUrl = MimeTypeMap.getFileExtensionFromUrl(name);
        if (TextUtils.isEmpty(fileExtensionFromUrl)) {
            fileExtensionFromUrl = "";
        }
        if (!MimeTypeMap.getSingleton().hasExtension(fileExtensionFromUrl)) {
            return C1495g.f1509j;
        }
        try {
            return C1495g.m568k(MimeTypeMap.getSingleton().getMimeTypeFromExtension(fileExtensionFromUrl));
        } catch (Exception unused) {
            return C1495g.f1509j;
        }
    }
}
