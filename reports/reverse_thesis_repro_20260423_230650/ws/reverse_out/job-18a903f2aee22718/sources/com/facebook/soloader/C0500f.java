package com.facebook.soloader;

import android.os.StrictMode;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/* JADX INFO: renamed from: com.facebook.soloader.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0500f extends E {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected final File f8353a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected int f8354b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected final List f8355c;

    public C0500f(File file, int i3) {
        this(file, i3, new String[0]);
    }

    @Override // com.facebook.soloader.E
    public String c() {
        return "DirectorySoSource";
    }

    @Override // com.facebook.soloader.E
    public int d(String str, int i3, StrictMode.ThreadPolicy threadPolicy) {
        return g(str, i3, this.f8353a, threadPolicy);
    }

    public File f(String str) {
        File file = new File(this.f8353a, str);
        if (file.exists()) {
            return file;
        }
        return null;
    }

    protected int g(String str, int i3, File file, StrictMode.ThreadPolicy threadPolicy) throws IOException {
        if (SoLoader.f8328b == null) {
            throw new IllegalStateException("SoLoader.init() not yet called");
        }
        if (this.f8355c.contains(str)) {
            p.a("SoLoader", str + " is on the denyList, skip loading from " + file.getCanonicalPath());
            return 0;
        }
        File fileF = f(str);
        if (fileF == null) {
            p.f("SoLoader", str + " file not found on " + file.getCanonicalPath());
            return 0;
        }
        String canonicalPath = fileF.getCanonicalPath();
        p.a("SoLoader", str + " file found at " + canonicalPath);
        if ((i3 & 1) != 0 && (this.f8354b & 2) != 0) {
            p.a("SoLoader", str + " loaded implicitly");
            return 2;
        }
        if ((this.f8354b & 1) != 0) {
            i iVar = new i(fileF);
            try {
                t.h(str, iVar, i3, threadPolicy);
                iVar.close();
            } catch (Throwable th) {
                try {
                    iVar.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
                throw th;
            }
        } else {
            p.a("SoLoader", "Not resolving dependencies for " + str);
        }
        try {
            SoLoader.f8328b.a(canonicalPath, i3);
            return 1;
        } catch (UnsatisfiedLinkError e3) {
            throw D.b(str, e3);
        }
    }

    public void h() {
        this.f8354b |= 1;
    }

    @Override // com.facebook.soloader.E
    public String toString() {
        String name;
        try {
            name = String.valueOf(this.f8353a.getCanonicalPath());
        } catch (IOException unused) {
            name = this.f8353a.getName();
        }
        return c() + "[root = " + name + " flags = " + this.f8354b + ']';
    }

    public C0500f(File file, int i3, String[] strArr) {
        this.f8353a = file;
        this.f8354b = i3;
        this.f8355c = Arrays.asList(strArr);
    }
}
