package com.facebook.imagepipeline.producers;

import a0.InterfaceC0223i;
import android.content.ContentResolver;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.ContactsContract;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class I extends L {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f6138d = new a(null);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final String[] f6139e = {"_id", "_data"};

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ContentResolver f6140c;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(Executor executor, InterfaceC0223i interfaceC0223i, ContentResolver contentResolver) {
        super(executor, interfaceC0223i);
        t2.j.f(executor, "executor");
        t2.j.f(interfaceC0223i, "pooledByteBufferFactory");
        t2.j.f(contentResolver, "contentResolver");
        this.f6140c = contentResolver;
    }

    private final N0.j g(Uri uri) throws IOException {
        try {
            ParcelFileDescriptor parcelFileDescriptorOpenFileDescriptor = this.f6140c.openFileDescriptor(uri, "r");
            if (parcelFileDescriptorOpenFileDescriptor == null) {
                throw new IllegalStateException("Required value was null.");
            }
            N0.j jVarE = e(new FileInputStream(parcelFileDescriptorOpenFileDescriptor.getFileDescriptor()), (int) parcelFileDescriptorOpenFileDescriptor.getStatSize());
            t2.j.e(jVarE, "getEncodedImage(...)");
            parcelFileDescriptorOpenFileDescriptor.close();
            return jVarE;
        } catch (FileNotFoundException unused) {
            return null;
        }
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected N0.j d(T0.b bVar) throws IOException {
        N0.j jVarG;
        InputStream inputStreamCreateInputStream;
        t2.j.f(bVar, "imageRequest");
        Uri uriV = bVar.v();
        t2.j.e(uriV, "getSourceUri(...)");
        if (!f0.f.j(uriV)) {
            if (f0.f.i(uriV) && (jVarG = g(uriV)) != null) {
                return jVarG;
            }
            InputStream inputStreamOpenInputStream = this.f6140c.openInputStream(uriV);
            if (inputStreamOpenInputStream != null) {
                return e(inputStreamOpenInputStream, -1);
            }
            throw new IllegalStateException("Required value was null.");
        }
        String string = uriV.toString();
        t2.j.e(string, "toString(...)");
        if (z2.g.i(string, "/photo", false, 2, null)) {
            inputStreamCreateInputStream = this.f6140c.openInputStream(uriV);
        } else {
            String string2 = uriV.toString();
            t2.j.e(string2, "toString(...)");
            if (z2.g.i(string2, "/display_photo", false, 2, null)) {
                try {
                    AssetFileDescriptor assetFileDescriptorOpenAssetFileDescriptor = this.f6140c.openAssetFileDescriptor(uriV, "r");
                    if (assetFileDescriptorOpenAssetFileDescriptor == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    inputStreamCreateInputStream = assetFileDescriptorOpenAssetFileDescriptor.createInputStream();
                } catch (IOException unused) {
                    throw new IOException("Contact photo does not exist: " + uriV);
                }
            } else {
                InputStream inputStreamOpenContactPhotoInputStream = ContactsContract.Contacts.openContactPhotoInputStream(this.f6140c, uriV);
                if (inputStreamOpenContactPhotoInputStream == null) {
                    throw new IOException("Contact photo does not exist: " + uriV);
                }
                inputStreamCreateInputStream = inputStreamOpenContactPhotoInputStream;
            }
        }
        if (inputStreamCreateInputStream != null) {
            return e(inputStreamCreateInputStream, -1);
        }
        throw new IllegalStateException("Required value was null.");
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected String f() {
        return "LocalContentUriFetchProducer";
    }
}
