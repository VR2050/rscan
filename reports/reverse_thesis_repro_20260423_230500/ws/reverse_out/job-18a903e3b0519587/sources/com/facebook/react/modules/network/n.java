package com.facebook.react.modules.network;

import B2.C;
import B2.x;
import Q2.AbstractC0207c;
import Q2.F;
import android.content.Context;
import android.net.Uri;
import android.util.Base64;
import i2.AbstractC0586n;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.List;
import java.util.ListIterator;
import java.util.zip.GZIPOutputStream;
import q2.AbstractC0663a;

/* JADX INFO: loaded from: classes.dex */
public final class n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final n f7153a = new n();

    public static final class a extends C {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ x f7154b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ InputStream f7155c;

        a(x xVar, InputStream inputStream) {
            this.f7154b = xVar;
            this.f7155c = inputStream;
        }

        @Override // B2.C
        public long a() {
            try {
                return this.f7155c.available();
            } catch (IOException unused) {
                return 0L;
            }
        }

        @Override // B2.C
        public x b() {
            return this.f7154b;
        }

        @Override // B2.C
        public void h(Q2.j jVar) {
            t2.j.f(jVar, "sink");
            F fC = null;
            try {
                fC = AbstractC0207c.a().c(this.f7155c);
                jVar.o(fC);
            } finally {
                if (fC != null) {
                    n.f7153a.b(fC);
                }
            }
        }
    }

    private n() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void b(F f3) {
        try {
            f3.close();
        } catch (RuntimeException e3) {
            throw e3;
        } catch (Exception unused) {
        }
    }

    public static final C c(x xVar, InputStream inputStream) {
        t2.j.f(inputStream, "inputStream");
        return new a(xVar, inputStream);
    }

    public static final C d(x xVar, String str) {
        t2.j.f(str, "body");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            GZIPOutputStream gZIPOutputStream = new GZIPOutputStream(byteArrayOutputStream);
            byte[] bytes = str.getBytes(z2.d.f10544b);
            t2.j.e(bytes, "getBytes(...)");
            gZIPOutputStream.write(bytes);
            gZIPOutputStream.close();
            C.a aVar = C.f97a;
            byte[] byteArray = byteArrayOutputStream.toByteArray();
            t2.j.e(byteArray, "toByteArray(...)");
            return C.a.g(aVar, xVar, byteArray, 0, 0, 12, null);
        } catch (IOException unused) {
            return null;
        }
    }

    public static final j e(C c3, i iVar) {
        t2.j.f(c3, "requestBody");
        t2.j.f(iVar, "listener");
        return new j(c3, iVar);
    }

    private final InputStream f(Context context, Uri uri) throws IOException {
        File fileCreateTempFile = File.createTempFile("RequestBodyUtil", "temp", context.getApplicationContext().getCacheDir());
        fileCreateTempFile.deleteOnExit();
        URL url = new URL(uri.toString());
        FileOutputStream fileOutputStream = new FileOutputStream(fileCreateTempFile);
        try {
            InputStream inputStreamOpenStream = url.openStream();
            try {
                ReadableByteChannel readableByteChannelNewChannel = Channels.newChannel(inputStreamOpenStream);
                try {
                    fileOutputStream.getChannel().transferFrom(readableByteChannelNewChannel, 0L, Long.MAX_VALUE);
                    FileInputStream fileInputStream = new FileInputStream(fileCreateTempFile);
                    AbstractC0663a.a(readableByteChannelNewChannel, null);
                    AbstractC0663a.a(inputStreamOpenStream, null);
                    AbstractC0663a.a(fileOutputStream, null);
                    return fileInputStream;
                } finally {
                }
            } finally {
            }
        } finally {
        }
    }

    public static final C g(String str) {
        t2.j.f(str, "method");
        int iHashCode = str.hashCode();
        if (iHashCode != 79599) {
            if (iHashCode != 2461856) {
                if (iHashCode != 75900968 || !str.equals("PATCH")) {
                    return null;
                }
            } else if (!str.equals("POST")) {
                return null;
            }
        } else if (!str.equals("PUT")) {
            return null;
        }
        return C.f97a.a(null, Q2.l.f2555e);
    }

    public static final InputStream h(Context context, String str) {
        List listG;
        t2.j.f(context, "context");
        t2.j.f(str, "fileContentUriStr");
        try {
            Uri uri = Uri.parse(str);
            String scheme = uri.getScheme();
            if (scheme != null && z2.g.u(scheme, "http", false, 2, null)) {
                n nVar = f7153a;
                t2.j.c(uri);
                return nVar.f(context, uri);
            }
            if (!z2.g.u(str, "data:", false, 2, null)) {
                return context.getContentResolver().openInputStream(uri);
            }
            List listC = new z2.f(",").c(str, 0);
            if (listC.isEmpty()) {
                listG = AbstractC0586n.g();
            } else {
                ListIterator listIterator = listC.listIterator(listC.size());
                while (listIterator.hasPrevious()) {
                    if (((String) listIterator.previous()).length() != 0) {
                        listG = AbstractC0586n.Q(listC, listIterator.nextIndex() + 1);
                        break;
                    }
                }
                listG = AbstractC0586n.g();
            }
            return new ByteArrayInputStream(Base64.decode(((String[]) listG.toArray(new String[0]))[1], 0));
        } catch (Exception e3) {
            Y.a.n("ReactNative", "Could not retrieve file for contentUri " + str, e3);
            return null;
        }
    }

    public static final boolean i(String str) {
        return z2.g.j("gzip", str, true);
    }
}
