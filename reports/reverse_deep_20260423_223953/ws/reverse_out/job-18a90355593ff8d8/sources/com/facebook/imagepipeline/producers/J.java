package com.facebook.imagepipeline.producers;

import a0.InterfaceC0223i;
import android.content.ContentResolver;
import android.database.Cursor;
import android.graphics.Rect;
import android.media.ExifInterface;
import android.net.Uri;
import android.provider.MediaStore;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class J extends L implements u0 {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final Class f6141d = J.class;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final String[] f6142e = {"_id", "_data"};

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final String[] f6143f = {"_data"};

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final Rect f6144g = new Rect(0, 0, 512, 384);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final Rect f6145h = new Rect(0, 0, 96, 96);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ContentResolver f6146c;

    public J(Executor executor, InterfaceC0223i interfaceC0223i, ContentResolver contentResolver) {
        super(executor, interfaceC0223i);
        this.f6146c = contentResolver;
    }

    private N0.j g(Uri uri, H0.g gVar) {
        Cursor cursorQuery;
        N0.j jVarJ;
        if (gVar == null || (cursorQuery = this.f6146c.query(uri, f6142e, null, null, null)) == null) {
            return null;
        }
        try {
            if (!cursorQuery.moveToFirst() || (jVarJ = j(gVar, cursorQuery.getLong(cursorQuery.getColumnIndex("_id")))) == null) {
                return null;
            }
            int columnIndex = cursorQuery.getColumnIndex("_data");
            if (columnIndex >= 0) {
                jVarJ.F0(i(cursorQuery.getString(columnIndex)));
            }
            return jVarJ;
        } finally {
            cursorQuery.close();
        }
    }

    private static int h(String str) {
        if (str == null) {
            return -1;
        }
        return (int) new File(str).length();
    }

    private static int i(String str) {
        if (str == null) {
            return 0;
        }
        try {
            return Y0.h.a(new ExifInterface(str).getAttributeInt("Orientation", 1));
        } catch (IOException e3) {
            Y.a.l(f6141d, e3, "Unable to retrieve thumbnail rotation for %s", str);
            return 0;
        }
    }

    private N0.j j(H0.g gVar, long j3) {
        Cursor cursorQueryMiniThumbnail;
        int columnIndex;
        int iK = k(gVar);
        if (iK == 0 || (cursorQueryMiniThumbnail = MediaStore.Images.Thumbnails.queryMiniThumbnail(this.f6146c, j3, iK, f6143f)) == null) {
            return null;
        }
        try {
            if (cursorQueryMiniThumbnail.moveToFirst() && (columnIndex = cursorQueryMiniThumbnail.getColumnIndex("_data")) >= 0) {
                String str = (String) X.k.g(cursorQueryMiniThumbnail.getString(columnIndex));
                if (new File(str).exists()) {
                    return e(new FileInputStream(str), h(str));
                }
            }
            return null;
        } finally {
            cursorQueryMiniThumbnail.close();
        }
    }

    private static int k(H0.g gVar) {
        Rect rect = f6145h;
        if (v0.b(rect.width(), rect.height(), gVar)) {
            return 3;
        }
        Rect rect2 = f6144g;
        return v0.b(rect2.width(), rect2.height(), gVar) ? 1 : 0;
    }

    @Override // com.facebook.imagepipeline.producers.u0
    public boolean b(H0.g gVar) {
        Rect rect = f6144g;
        return v0.b(rect.width(), rect.height(), gVar);
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected N0.j d(T0.b bVar) {
        Uri uriV = bVar.v();
        if (f0.f.i(uriV)) {
            return g(uriV, bVar.r());
        }
        return null;
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected String f() {
        return "LocalContentUriThumbnailFetchProducer";
    }
}
